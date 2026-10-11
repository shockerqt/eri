-- NULL preserves the immutable first-party classification of existing grants.
-- Dynamic grants carry the same security binding through the existing lifecycle.
ALTER TABLE browser_authorizations ADD COLUMN cimd_binding jsonb;
ALTER TABLE authorization_codes ADD COLUMN cimd_binding jsonb;
ALTER TABLE refresh_families ADD COLUMN cimd_binding jsonb;

ALTER TABLE browser_authorizations ADD CONSTRAINT browser_cimd_binding_shape CHECK (
    cimd_binding IS NULL OR COALESCE(
        jsonb_typeof(cimd_binding) = 'object'
        AND cimd_binding->'version' = '1'::jsonb
        AND jsonb_typeof(cimd_binding->'client_id') = 'string'
        AND cimd_binding->>'client_id' = client_id
        AND jsonb_typeof(cimd_binding->'redirects') = 'array'
        AND jsonb_typeof(cimd_binding->'refresh_allowed') = 'boolean'
        AND octet_length(cimd_binding::text) <= 49152, false)
);
ALTER TABLE authorization_codes ADD CONSTRAINT code_cimd_binding_shape CHECK (
    cimd_binding IS NULL OR COALESCE(
        jsonb_typeof(cimd_binding) = 'object'
        AND cimd_binding->'version' = '1'::jsonb
        AND jsonb_typeof(cimd_binding->'client_id') = 'string'
        AND cimd_binding->>'client_id' = client_id
        AND jsonb_typeof(cimd_binding->'redirects') = 'array'
        AND jsonb_typeof(cimd_binding->'refresh_allowed') = 'boolean'
        AND octet_length(cimd_binding::text) <= 49152, false)
);
ALTER TABLE refresh_families ADD CONSTRAINT family_cimd_binding_shape CHECK (
    cimd_binding IS NULL OR COALESCE(
        jsonb_typeof(cimd_binding) = 'object'
        AND cimd_binding->'version' = '1'::jsonb
        AND jsonb_typeof(cimd_binding->'client_id') = 'string'
        AND cimd_binding->>'client_id' = client_id
        AND jsonb_typeof(cimd_binding->'redirects') = 'array'
        AND jsonb_typeof(cimd_binding->'refresh_allowed') = 'boolean'
        AND octet_length(cimd_binding::text) <= 49152, false)
);
