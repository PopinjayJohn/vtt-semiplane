-- 0001_init: the whole §6.2 schema.
--
-- Two columns here are not in the plan's §6.2 text, and both are forced by the
-- plan's own hard rules rather than chosen for convenience. Each is marked at
-- its definition.

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- keys: 'schema_version', 'boot_state', 'fts_generation', 'installed_at',
-- 'last_backup', 'last_change_at', 'authz_generation'

CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','dm','player')),
  pw_hash       BLOB,          -- Argon2id
  pw_salt       BLOB NOT NULL,
  created_at    TEXT NOT NULL,
  disabled_at   TEXT
);

CREATE TABLE sessions (
  id          TEXT PRIMARY KEY,        -- sha256(cookie token); raw token never stored
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  user_agent  TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE invites (
  token_hash TEXT PRIMARY KEY,         -- sha256; raw token only in the emailed/emitted URL
  role       TEXT NOT NULL,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  redeemed_at TEXT,
  redeemed_by INTEGER REFERENCES users(id)
);
CREATE INDEX invites_expiry ON invites(expires_at) WHERE redeemed_at IS NULL;

CREATE TABLE pages (
  id           INTEGER PRIMARY KEY,
  path         TEXT NOT NULL UNIQUE,          -- vault-relative, forward slashes
  basename     TEXT NOT NULL,
  title        TEXT NOT NULL,
  frontmatter  TEXT NOT NULL DEFAULT '',      -- raw YAML bytes, verbatim
  content_hash BLOB NOT NULL,                 -- sha256 of the whole file
  mtime_unix   INTEGER NOT NULL,
  size_bytes   INTEGER NOT NULL,
  page_type    TEXT NOT NULL DEFAULT 'note',
  system_id    TEXT,                          -- owning plugin, NULL for core
  owner_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE INDEX pages_path    ON pages(path);
CREATE INDEX pages_owner   ON pages(owner_id);
CREATE INDEX pages_type    ON pages(page_type, system_id);
CREATE INDEX pages_updated ON pages(updated_at DESC);
CREATE INDEX pages_title   ON pages(title COLLATE NOCASE);

-- Every user who may read a page's private secrets. pages.owner_id (the primary
-- owner) is ALWAYS also a row here, so this table is the single source of truth
-- for ownership; pages.owner_id exists only for the common single-owner case.
CREATE TABLE page_owners (
  page_id  INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  is_owner INTEGER NOT NULL DEFAULT 0,
  added_at TEXT NOT NULL,
  PRIMARY KEY (page_id, user_id)
);
CREATE INDEX page_owners_user ON page_owners(user_id, page_id);

CREATE TABLE page_aliases (
  page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
  alias   TEXT NOT NULL,
  PRIMARY KEY (page_id, alias)
);
CREATE INDEX page_aliases_alias ON page_aliases(alias COLLATE NOCASE);

CREATE TABLE tags (
  name TEXT PRIMARY KEY          -- lowercased, no '#'
);
-- secret_id is an addition to §6.2. §5.4 requires every extracted fact to carry
-- the secret it came from, and §6.4 requires tag counts to be filtered with
-- SecretVisibleSQL; a predicate needs a secret row to evaluate, and a page that
-- uses a tag both publicly and inside a secret needs two rows to say so. It is
-- NOT NULL DEFAULT '' rather than NULL because it is part of the primary key,
-- where NULLs would defeat uniqueness. '' means public, matching links.
CREATE TABLE page_tags (
  page_id   INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
  tag       TEXT NOT NULL REFERENCES tags(name) ON DELETE CASCADE,
  source    TEXT NOT NULL CHECK (source IN ('frontmatter','inline')),
  secret_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (page_id, tag, source, secret_id)
);
CREATE INDEX page_tags_tag ON page_tags(tag, page_id);

CREATE TABLE links (
  id              INTEGER PRIMARY KEY,
  source_page_id  INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
  target_page_id  INTEGER REFERENCES pages(id) ON DELETE SET NULL,
  target_raw      TEXT NOT NULL,             -- exactly as written
  kind            TEXT NOT NULL,             -- wikilink|embed|markdown|attachment|tag
  alias           TEXT,
  heading         TEXT,
  block_ref       TEXT,
  secret_id       TEXT,                      -- NULL ⇒ public
  line            INTEGER NOT NULL
);
CREATE INDEX links_source     ON links(source_page_id, kind);
CREATE INDEX links_target     ON links(target_page_id) WHERE target_page_id IS NOT NULL;
CREATE INDEX links_unresolved ON links(target_raw) WHERE target_page_id IS NULL;
CREATE INDEX links_secret     ON links(secret_id) WHERE secret_id IS NOT NULL;

CREATE TABLE headings (
  page_id   INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
  ordinal   INTEGER NOT NULL,
  level     INTEGER NOT NULL,
  slug      TEXT NOT NULL,
  text      TEXT NOT NULL,
  secret_id TEXT
);
CREATE INDEX headings_page ON headings(page_id, ordinal);

CREATE TABLE secrets (
  id          TEXT PRIMARY KEY,              -- 12 lowercase hex chars
  page_id     INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
  ordinal     INTEGER NOT NULL,
  visibility  TEXT NOT NULL CHECK (visibility IN ('private','dm','table')),
  author_id   INTEGER NOT NULL REFERENCES users(id),
  -- title is an addition to §6.2. The fence directive carries an optional
  -- title= (§8.1) and the reveal UI needs it; §6.2 simply omitted the column.
  title       TEXT,
  body        TEXT NOT NULL,                 -- plaintext (D4)
  body_hash   BLOB NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX secrets_page ON secrets(page_id, ordinal);
CREATE INDEX secrets_vis  ON secrets(visibility);

CREATE TABLE secret_events (                -- append-only audit
  id          INTEGER PRIMARY KEY,
  secret_id   TEXT NOT NULL,
  actor_id    INTEGER NOT NULL REFERENCES users(id),
  action      TEXT NOT NULL CHECK (action IN ('create','reveal','revoke','edit','delete','view_denied')),
  from_vis    TEXT,
  to_vis      TEXT,
  at          TEXT NOT NULL
);
CREATE INDEX secret_events_secret ON secret_events(secret_id, at DESC);
CREATE INDEX secret_events_actor  ON secret_events(actor_id, at DESC);

CREATE TABLE revisions (
  id         INTEGER PRIMARY KEY,
  page_id    INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
  content_hash BLOB NOT NULL,
  content    TEXT NOT NULL,
  author_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  at         TEXT NOT NULL,
  source     TEXT NOT NULL CHECK (source IN ('app','external','create','delete'))
);
CREATE INDEX revisions_page ON revisions(page_id, at DESC);

-- No secret_id: visibility is a property of the referencing link, not the file.
-- Authorization is evaluated per link at serve time (see §8.8).
CREATE TABLE attachments (
  id         INTEGER PRIMARY KEY,
  page_id    INTEGER REFERENCES pages(id) ON DELETE CASCADE,
  path       TEXT NOT NULL UNIQUE,
  mime       TEXT NOT NULL,
  size_bytes INTEGER NOT NULL
);
CREATE INDEX attachments_page ON attachments(page_id);

CREATE TABLE plugin_migrations (
  plugin_id TEXT NOT NULL, version INTEGER NOT NULL,
  applied_at TEXT NOT NULL, PRIMARY KEY (plugin_id, version)
);

CREATE TABLE selfwrites (                   -- suppresses fsnotify feedback loops
  path TEXT PRIMARY KEY, hash BLOB NOT NULL, expires_at TEXT NOT NULL
);

-- FTS: public content only. Secret bodies NEVER enter this table.
CREATE TABLE page_text (
  page_id  INTEGER PRIMARY KEY REFERENCES pages(id) ON DELETE CASCADE,
  title    TEXT NOT NULL,
  headings TEXT NOT NULL,
  body     TEXT NOT NULL
);
CREATE VIRTUAL TABLE page_fts USING fts5(
  title, headings, body,
  content='page_text', content_rowid='page_id',
  tokenize = "unicode61 remove_diacritics 2 tokenchars '_-'",
  prefix = '2 3 4'
);

-- FTS: revealed secrets only, populated iff visibility='table'
--
-- fts_rowid is an addition to §6.2 and a correction of it. FTS5's
-- content_rowid must name an INTEGER key: with §6.2's TEXT secret_id, every
-- insert into secret_fts fails with "datatype mismatch (20)" and every MATCH
-- returns nothing. secret_id remains the primary key and the foreign key; the
-- surrogate is written by the same statement that populates the body, and is
-- never exposed outside this pair of tables.
CREATE TABLE secret_text (
  fts_rowid INTEGER PRIMARY KEY,
  secret_id TEXT NOT NULL UNIQUE REFERENCES secrets(id) ON DELETE CASCADE,
  body      TEXT NOT NULL
);
CREATE VIRTUAL TABLE secret_fts USING fts5(
  body, content='secret_text', content_rowid='fts_rowid',
  tokenize = "unicode61 remove_diacritics 2 tokenchars '_-'",
  prefix = '2 3 4'
);

PRAGMA user_version = 1;
