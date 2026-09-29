-- 0002_link_offsets: the byte offsets of a link's target token.
--
-- The bulk link updater (§5.6) makes a stale preview harmless by re-verifying
-- the bytes at a recorded offset before it splices anything, so a links row has
-- to carry where its target token starts and how long it is. §6.2's links table
-- has neither column.
--
-- byte_start = -1 means "not recorded", and it is the value every row written
-- before this migration holds: ALTER TABLE fills the default into the rows that
-- already exist. The sentinel is negative rather than zero because zero is a
-- real offset — a link written in the first byte of a file — and a caller that
-- cannot tell the two apart would verify an empty span and call it a conflict on
-- every single link in the vault. An unrecorded offset must read as absent, not
-- as plausible.

ALTER TABLE links ADD COLUMN byte_start INTEGER NOT NULL DEFAULT -1;
ALTER TABLE links ADD COLUMN byte_len   INTEGER NOT NULL DEFAULT 0;

PRAGMA user_version = 2;
