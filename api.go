package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type server struct {
	db *gorm.DB
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// containsDotFile reports whether name contains a path element starting with a period.
// The name is assumed to be a delimited by forward slashes, as guaranteed
// by the http.FileSystem interface.
func containsDotFile(name string) bool {
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

// dotFileHidingFile is the http.File use in dotFileHidingFileSystem.
// It is used to wrap the Readdir method of http.File so that we can
// remove files and directories that start with a period from its output.
type dotFileHidingFile struct {
	http.File
}

// Readdir is a wrapper around the Readdir method of the embedded File
// that filters out all files that start with a period in their name.
func (f dotFileHidingFile) Readdir(n int) (fis []fs.FileInfo, err error) {
	files, err := f.File.Readdir(n)
	for _, file := range files { // Filters out the dot files
		if !strings.HasPrefix(file.Name(), ".") {
			fis = append(fis, file)
		}
	}
	if err == nil && n > 0 && len(fis) == 0 {
		err = io.EOF
	}
	return
}

// dotFileHidingFileSystem is an http.FileSystem that hides
// hidden "dot files" from being served.
type dotFileHidingFileSystem struct {
	http.FileSystem
}

// Open is a wrapper around the Open method of the embedded FileSystem
// that serves a 403 permission error when name has a file or directory
// with whose name starts with a period in its path.
func (fsys dotFileHidingFileSystem) Open(name string) (http.File, error) {
	if containsDotFile(name) { // If dot file, return 403 response
		return nil, fs.ErrPermission
	}

	file, err := fsys.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	return dotFileHidingFile{file}, nil
}
func middleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The "/" pattern matches everything, so we need to check
		// that we're at the root here.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		log.Println(r.URL.Path, "homepage middleWare")
		next.ServeHTTP(w, r)
		log.Println(r.URL.Path, "homepage middleWare again")
	})
}
func (s *server) currentUser(r *http.Request) *User {
	token := bearerToken(r)
	if token == "" {
		return nil
	}
	var user User
	err := s.db.
		Joins("JOIN device ON device.user_id = user.id").
		Joins("JOIN session ON session.device_id = device.id").
		Where("session.hash = ? AND session.expired_at > ? AND device.status = ?",
			hashToken(token), time.Now().UTC(), "active").
		First(&user).Error
	if err != nil {
		return nil
	}
	return &user
}
func (s *server) creatNewUser(name, pwd string) (User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	user := User{Name: name}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		return tx.Create(&Auth{UserID: user.ID, Password: string(hash)}).Error
	})
	return user, err
}
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	log.Print(r.PostForm)
	var user User
	var nameF = strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	var pwdF = r.FormValue("password")
	if len(nameF) < 3 || len(nameF) > 24 || len(pwdF) < 6 || len(pwdF) > 72 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Username: 3 to 24 characters. Password: 6 to 72 characters."})
		return
	}
	err := s.db.Joins("Auth").First(&user, "user.name = ?", nameF).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		user, err = s.creatNewUser(nameF, pwdF) // first login creates the account
		if err != nil {
			log.Println("create user:", err)
			writeJSON(w, http.StatusConflict, map[string]string{"error": "That username is taken or the server is busy. Try again."})
			return
		}
	case err != nil:
		log.Println("find user:", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Something went wrong. Try again."})
		return
	case user.Auth == nil || bcrypt.CompareHashAndPassword([]byte(user.Auth.Password), []byte(pwdF)) != nil:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Username or password is wrong."})
		return
	}
	token, expires, err := s.newSession(user.ID, r.UserAgent())
	if err != nil {
		log.Println("new session:", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Something went wrong. Try again."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   user.Name,
		"token":      token,
		"expires_at": expires,
	})
}
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if token := bearerToken(r); token != "" {
		s.db.Where("hash = ?", hashToken(token)).Delete(&Session{})
	}
	w.WriteHeader(http.StatusNoContent)
}
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// 32 random bytes as text. This goes in the cookie, never in the database.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (s *server) newSession(userID uint, ua string) (string, time.Time, error) {
	token, err := newToken()
	if err != nil {
		return "", time.Time{}, err
	}
	if len(ua) > 100 {
		ua = ua[:100]
	}
	hr, err := time.ParseDuration(MyEnv["SESSION_LIFE"]) // SESSION_DAYS=30
	if err != nil || hr <= 0 {
		hr = 6*time.Hour // default when missing or invalid
	}
	expires := time.Now().UTC().Add(hr)
	err = s.db.Transaction(func(tx *gorm.DB) error {
		device := Device{UserID: userID, Name: ua}
		if err := tx.Create(&device).Error; err != nil {
			return err
		}
		return tx.Create(&Session{DeviceID: device.ID, Hash: hashToken(token), ExpiredAt: expires}).Error
	})
	return token, expires, err
}

var (
	prefixRe       = regexp.MustCompile(`^[a-z0-9_-]{2,20}$`)
	reservedPrefix = map[string]bool{"api": true, "user": true}
	errPrefixTaken = errors.New("prefix taken")
)

const codeAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0 O 1 l I

type shortenResponse struct {
	ShortURL string `json:"short_url"`
	Code     string `json:"code"`
	Prefix   string `json:"prefix"`
	URL      string `json:"url"`
}

// BASE_URL in .env (for example https://hopl.to), otherwise built from the request.
func baseURL(r *http.Request) string {
	if b := strings.TrimRight(MyEnv["BASE_URL"], "/"); b != "" {
		return b
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func normalizeURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return "", false
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.Contains(u.Hostname(), ".") {
		return "", false
	}
	return u.String(), true
}

func randomCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b), nil
}

// Find a code that is not used yet under this prefix (or among prefix-less links).
func freeCode(tx *gorm.DB, prefixID *uint) (string, error) {
	for i := 0; i < 8; i++ {
		code, err := randomCode(6)
		if err != nil {
			return "", err
		}
		q := tx.Model(&Short{}).Where("link = ?", code)
		if prefixID != nil {
			q = q.Where("prefix_id = ?", *prefixID)
		} else {
			q = q.Where("prefix_id IS NULL")
		}
		var n int64
		if err := q.Count(&n).Error; err != nil {
			return "", err
		}
		if n == 0 {
			return code, nil
		}
	}
	return "", errors.New("no free code")
}

// Use the prefix if it is yours, create it if it is new, refuse it if someone else owns it.
func claimPrefix(tx *gorm.DB, userID uint, name string) (Prefix, error) {
	var p Prefix
	err := tx.Where("name = ?", name).First(&p).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		p = Prefix{UserID: userID, Name: name}
		if err := tx.Create(&p).Error; err != nil {
			return Prefix{}, errPrefixTaken // someone created it a moment ago
		}
		return p, nil
	case err != nil:
		return Prefix{}, err
	case p.UserID != userID || p.Status != "active":
		return Prefix{}, errPrefixTaken
	}
	return p, nil
}

func (s *server) shorten(w http.ResponseWriter, r *http.Request) {
	origin, ok := normalizeURL(r.FormValue("url"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Enter a full web address, for example https://example.com/page."})
		return
	}

	user := s.currentUser(r) // nil for guests
	prefixName := strings.ToLower(strings.TrimSpace(r.FormValue("prefix")))
	if prefixName != "" {
		if user == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Log in to use a prefix."})
			return
		}
		if !prefixRe.MatchString(prefixName) || reservedPrefix[prefixName] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Prefix must be 2 to 20 letters, numbers, dashes or underscores."})
			return
		}
	}

	var short Short
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var prefixID *uint
		if prefixName != "" {
			p, err := claimPrefix(tx, user.ID, prefixName)
			if err != nil {
				return err
			}
			prefixID = &p.ID
		}
		code, err := freeCode(tx, prefixID)
		if err != nil {
			return err
		}
		short = Short{PrefixID: prefixID, Link: code, Origin: origin}
		if err := tx.Create(&short).Error; err != nil {
			return err
		}
		if user != nil { // guests have no user_short row
			return tx.Create(&UserShort{UserID: user.ID, ShortID: short.ID}).Error
		}
		return nil
	})
	if errors.Is(err, errPrefixTaken) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "That prefix belongs to another account. Try a different one."})
		return
	}
	if err != nil {
		log.Println("shorten:", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Something went wrong. Try again."})
		return
	}

	full := baseURL(r) + "/"
	if prefixName != "" {
		full += prefixName + "/"
	}
	writeJSON(w, http.StatusOK, shortenResponse{
		ShortURL: full + short.Link,
		Code:     short.Link,
		Prefix:   prefixName,
		URL:      origin,
	})
}

// Handles /{code} and /{prefix}/{code}.
func (s *server) redirect(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	prefix := strings.ToLower(r.PathValue("prefix")) // "" on /{code}

	q := s.db.Where("short.link = ? AND short.status = ? AND (short.expired_at IS NULL OR short.expired_at > ?)",
		code, "active", time.Now().UTC())
	if prefix == "" {
		q = q.Where("short.prefix_id IS NULL")
	} else {
		q = q.Joins("JOIN prefix ON prefix.id = short.prefix_id").
			Where("prefix.name = ? AND prefix.status = ?", prefix, "active")
	}

	var short Short
	if err := q.First(&short).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, short.Origin, http.StatusFound) // 302, so edits and deletes take effect
}

// What goes in session.hash.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (s *server) me(w http.ResponseWriter, r *http.Request) { /* use s.db */ }

func StartSeverMux(mux *http.ServeMux, db *gorm.DB) {
	s := &server{db: db}
	mux.HandleFunc("POST /user/login", s.login)
	mux.HandleFunc("POST /user/logout", s.logout)
	mux.HandleFunc("POST /api/shorten", s.shorten)
	mux.HandleFunc("GET /{code}", s.redirect)
	mux.HandleFunc("GET /{prefix}/{code}", s.redirect)
	mux.HandleFunc("GET /user/me", s.me)
	fsys := dotFileHidingFileSystem{http.Dir(".")}
	mux.Handle("GET /", middleWare(http.FileServer(fsys)))
	log.Fatal(http.ListenAndServe(":"+MyEnv["PORT"], mux))
}
