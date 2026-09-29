-- 0003_attachment_scope: an attachments row belongs to a page, not to the vault.
--
-- §6.2 declares attachments.path UNIQUE, which makes the table a claim about
-- the *file*: one row, one path, for the whole campaign. §8.8's rule is about
-- the *reference* — serve the file if at least one referencing links row for
-- that page is public or inside a secret the principal may read — and the serve
-- path reads the row through the page: store.AttachmentVisibleTo and
-- store.ListAttachmentsByPage both key on page_id. A campaign-wide unique path
-- makes the two halves disagree about what a row means, and it disagrees in the
-- direction that loses: a second page referencing an image the first page already
-- recorded cannot have a row of its own, so the route authorizes the request
-- against that page's links and then has no row to serve it from. An image a
-- reader can plainly see on page two is a 404 on page two.
--
-- So the constraint becomes UNIQUE(path, page_id): one row per referencing page,
-- one shared path, and the file itself is still a single fact in the vault. This
-- is the rebuild idiom rather than a drop-and-recreate because the table holds
-- rows — a campaign's attachment inventory — and because SQLite cannot drop a
-- table-level UNIQUE constraint in place. The new table is built under a
-- temporary name, the rows are copied, and only then does the old table go: at
-- no point does the schema have two tables the same name, and the copy cannot
-- violate the new constraint because UNIQUE(path) already implies
-- UNIQUE(path, page_id).
--
-- The index is recreated by hand because DROP TABLE takes its indexes with it,
-- and it is recreated under its original name so a migrated database and a fresh
-- one are byte-identical in sqlite_schema.

CREATE TABLE attachments_v3 (
  id         INTEGER PRIMARY KEY,
  page_id    INTEGER REFERENCES pages(id) ON DELETE CASCADE,
  path       TEXT NOT NULL,
  mime       TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  UNIQUE(path, page_id)
);

INSERT INTO attachments_v3 (id, page_id, path, mime, size_bytes)
  SELECT id, page_id, path, mime, size_bytes FROM attachments;

DROP TABLE attachments;

ALTER TABLE attachments_v3 RENAME TO attachments;

CREATE INDEX attachments_page ON attachments(page_id);

PRAGMA user_version = 3;
