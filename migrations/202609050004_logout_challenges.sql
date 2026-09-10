CREATE TABLE logout_challenges (
    id uuid PRIMARY KEY,
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash)=32),
    session_id uuid NOT NULL REFERENCES provider_sessions(id) ON DELETE CASCADE,
    client_id text NOT NULL,
    post_logout_redirect_uri text NOT NULL,
    downstream_state text,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX logout_challenges_expiry_idx ON logout_challenges(expires_at);
CREATE INDEX logout_challenges_session_idx ON logout_challenges(session_id);
