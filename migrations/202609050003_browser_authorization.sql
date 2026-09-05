ALTER TABLE provider_sessions ADD COLUMN upstream_auth_time timestamptz;
ALTER TABLE authorization_codes ADD COLUMN oidc_nonce text;
ALTER TABLE authorization_codes ADD COLUMN upstream_auth_time timestamptz;
ALTER TABLE refresh_families ADD COLUMN upstream_auth_time timestamptz;

CREATE TABLE user_profiles (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    name text,
    given_name text,
    family_name text,
    picture text,
    verified_email text,
    updated_at timestamptz NOT NULL
);

CREATE TABLE browser_authorizations (
    id uuid PRIMARY KEY,
    stage text NOT NULL CHECK (stage IN ('awaiting_google','callback_claimed','awaiting_consent','approved','denied','failed','expired')),
    upstream_state_hash bytea UNIQUE CHECK (upstream_state_hash IS NULL OR octet_length(upstream_state_hash)=32),
    browser_binding_hash bytea CHECK (browser_binding_hash IS NULL OR octet_length(browser_binding_hash)=32),
    upstream_nonce text,
    upstream_verifier text,
    claim_hash bytea UNIQUE CHECK (claim_hash IS NULL OR octet_length(claim_hash)=32),
    csrf_hash bytea CHECK (csrf_hash IS NULL OR octet_length(csrf_hash)=32),
    session_id uuid REFERENCES provider_sessions(id) ON DELETE CASCADE,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    resource text NOT NULL,
    code_challenge text NOT NULL,
    downstream_state text,
    oidc_nonce text,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at <= created_at + interval '10 minutes')
);

CREATE INDEX browser_authorizations_expiry_idx ON browser_authorizations(expires_at);
CREATE INDEX browser_authorizations_session_idx ON browser_authorizations(session_id);
