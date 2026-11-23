package main

import (
	"net/http"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var MyEnv map[string]string

func openDB() *gorm.DB {
	db, err := gorm.Open(
		sqlite.Open("hopl.db?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"),
		&gorm.Config{
			NamingStrategy: schema.NamingStrategy{SingularTable: true}, // table "user", not "users"
		},
	)
	if err != nil {
		panic(err)
	}

	err = db.AutoMigrate(
		&User{}, &Auth{}, &Device{}, &Session{},
		&Prefix{}, &Short{}, &UserShort{},
	)
	if err != nil {
		panic(err)
	}
	return db
}
func init() {
	var err error
	MyEnv, err = godotenv.Read()
	if err != nil {
		panic("Error loading .env file")
	}
}
func run() {
	// start db
	db := openDB()
	// start sever
	mux := http.NewServeMux()
	StartSeverMux(mux, db)
}
func main() {
	run()
}
