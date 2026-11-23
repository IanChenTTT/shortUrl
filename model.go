package main

import (
	"time"

	"gorm.io/gorm"
)

// Shared columns: id, created_at, updated_at (GORM fills the two timestamps automatically).
type Base struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type User struct {
	Base
	Name      string         `gorm:"not null;uniqueIndex;type:text collate nocase"`
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Auth     *Auth
	Devices  []Device
	Prefixes []Prefix
}

type Auth struct {
	Base
	UserID    uint           `gorm:"not null;uniqueIndex"`
	Password  string         `gorm:"not null" json:"-"` // bcrypt or argon2 hash, never plain text
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type Device struct {
	Base
	UserID uint `gorm:"not null;index"`
	Name   string
	Status string `gorm:"not null;default:active"`

	Session *Session
}

type Session struct {
	Base
	DeviceID  uint      `gorm:"not null;index"`
	Hash      string    `gorm:"not null;uniqueIndex" json:"-"` // hash of the random cookie value
	ExpiredAt time.Time `gorm:"not null"`
}

type Prefix struct {
	Base
	UserID uint   `gorm:"not null;index"`
	Name   string `gorm:"not null;uniqueIndex;check:name = lower(name) AND length(name) BETWEEN 2 AND 20"`
	Status string `gorm:"not null;default:active"`

	Shorts []Short
}

type Short struct {
	Base
	PrefixID  *uint  `gorm:"uniqueIndex:short_prefixed,priority:1,where:prefix_id IS NOT NULL"` // nil = no prefix
	Link      string `gorm:"not null;uniqueIndex:short_prefixed,priority:2,where:prefix_id IS NOT NULL;uniqueIndex:short_plain,where:prefix_id IS NULL"`
	Origin    string `gorm:"not null"`
	Status    string `gorm:"not null;default:active"`
	ExpiredAt *time.Time

	Prefix *Prefix
}

// Only links made by logged-in users have a row here. Guest links have none.
type UserShort struct {
	UserID  uint `gorm:"primaryKey"`
	ShortID uint `gorm:"primaryKey;uniqueIndex"`

	User  User
	Short Short
}
