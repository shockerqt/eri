ALTER TABLE browser_authorizations
    ADD COLUMN allow_pre_authorization boolean NOT NULL DEFAULT false;
