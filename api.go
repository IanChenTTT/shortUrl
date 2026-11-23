package main

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type server struct {
	db *gorm.DB
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
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	log.Print(r.PostForm)
	var user User
	var nameF = strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	var pwdF = r.FormValue("password")
	result := s.db.Joins("Auth").First(&user, "user.name = ?", nameF)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		err, _ := creatNewUser(s, nameF, pwdF)
		if err != nil {
			log.Fatal(err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"username": user.Name})
		return
	}
	// when logging in: compare the typed password with the stored hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Auth.Password), []byte(pwdF))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Username or password is wrong."})
	}
}
func creatNewUser(s *server, nameF string, pwdF string) (error, int) {
	var auth Auth
	log.Print("create user")
	newUser := User{Name: nameF}
	result := s.db.Create(&newUser)
	if result.Error != nil {
		log.Fatal("can't user")
		return result.Error, 0
	}
	log.Print(newUser.ID)
	hash, err := bcrypt.GenerateFromPassword([]byte(pwdF), bcrypt.DefaultCost)
	if err != nil {
		return err, 0
	}
	auth.Password = string(hash)
	auth.UserID = newUser.ID
	result = s.db.Create(&auth)
	if result.Error != nil {
		log.Fatal("can't create password")
		return result.Error, 0
	}
	log.Print(auth.ID)
	return nil, int(newUser.ID)
}
func (s *server) shorten(w http.ResponseWriter, r *http.Request) { /* use s.db */ }
func (s *server) me(w http.ResponseWriter, r *http.Request)      { /* use s.db */ }

func StartSeverMux(mux *http.ServeMux, db *gorm.DB) {
	s := &server{db: db}
	mux.HandleFunc("POST /user/login", s.login)
	mux.HandleFunc("POST /api/shorten", s.shorten)
	mux.HandleFunc("GET /user/me", s.me)
	fsys := dotFileHidingFileSystem{http.Dir(".")}
	mux.Handle("GET /", middleWare(http.FileServer(fsys)))
	log.Fatal(http.ListenAndServe(":"+MyEnv["PORT"], mux))
}
