CREATE TABLE provider_sessions (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_time timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at <= auth_time + interval '30 days')
);

CREATE TABLE authorization_codes (
    id uuid PRIMARY KEY,
    code_hash bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    session_id uuid NOT NULL REFERENCES provider_sessions(id) ON DELETE CASCADE,
    client_id text NOT NULL CHECK (client_id <> ''),
    redirect_uri text NOT NULL CHECK (redirect_uri <> ''),
    scopes text[] NOT NULL,
    resource text NOT NULL CHECK (resource <> ''),
    code_challenge text NOT NULL,
    issue_refresh_token boolean NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at <= issued_at + interval '60 seconds')
);

CREATE TABLE refresh_families (
    id uuid PRIMARY KEY,
    source_code_id uuid NOT NULL UNIQUE REFERENCES authorization_codes(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES provider_sessions(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id text NOT NULL,
    scopes text[] NOT NULL,
    resource text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at <= issued_at + interval '30 days')
);

CREATE TABLE refresh_token_members (
    id uuid PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES refresh_families(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    issued_at timestamptz NOT NULL,
    consumed_at timestamptz,
    successor_id uuid REFERENCES refresh_token_members(id)
);

CREATE INDEX provider_sessions_expiry_idx ON provider_sessions (expires_at);
CREATE INDEX authorization_codes_expiry_idx ON authorization_codes (expires_at);
CREATE INDEX refresh_families_expiry_idx ON refresh_families (expires_at);
CREATE INDEX refresh_token_members_family_idx ON refresh_token_members (family_id);
