PRAGMA foreign_keys = ON;      -- must be run on every new connection
PRAGMA journal_mode = WAL;     -- better for many reads with a few writes

CREATE TABLE "user" (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at TEXT
);

CREATE TABLE auth (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL UNIQUE REFERENCES "user"(id),
  password   TEXT NOT NULL,                  -- bcrypt or argon2 hash
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at TEXT
);

CREATE TABLE device (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES "user"(id),
  name       TEXT,
  status     TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE session (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id  INTEGER NOT NULL REFERENCES device(id),
  hash       TEXT NOT NULL UNIQUE,           -- hash of the random cookie value
  expired_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE prefix (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES "user"(id),
  name       TEXT NOT NULL UNIQUE
             CHECK (name = lower(name)
                    AND length(name) BETWEEN 2 AND 20
                    AND name NOT GLOB '*[^a-z0-9_-]*'),
  status     TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE short (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  prefix_id  INTEGER REFERENCES prefix(id),  -- NULL = no prefix
  link       TEXT NOT NULL,                  -- short code, e.g. k7Qp2x
  origin     TEXT NOT NULL,                  -- long URL
  status     TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expired_at TEXT
);
CREATE UNIQUE INDEX short_prefixed ON short (prefix_id, link) WHERE prefix_id IS NOT NULL;
CREATE UNIQUE INDEX short_plain    ON short (link)            WHERE prefix_id IS NULL;

CREATE TABLE user_short (
  user_id  INTEGER NOT NULL REFERENCES "user"(id),
  short_id INTEGER NOT NULL UNIQUE REFERENCES short(id),
  PRIMARY KEY (user_id, short_id)
);
