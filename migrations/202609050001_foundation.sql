CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE external_identities (
    issuer text NOT NULL CHECK (issuer = 'https://accounts.google.com'),
    subject text NOT NULL CHECK (subject <> ''),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject),
    UNIQUE (user_id, issuer)
);

CREATE INDEX external_identities_user_id_idx ON external_identities (user_id);
