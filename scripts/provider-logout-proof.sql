-- Read-only provider lifecycle evidence for one public 32-character operation reference.
-- Run only after the client B refresh probe; see docs/provider-logout-proof.md.
BEGIN READ ONLY;
WITH p AS (
  SELECT op, clock_timestamp() AS proof_at
  FROM (SELECT :'operation_id'::text AS op) input
  WHERE op ~ '^[a-f0-9]{32}$'
), codes AS (
  SELECT c.id,c.oidc_nonce,c.session_id,c.client_id,c.resource,c.consumed_at,
         substring(c.oidc_nonce from '\.([AB])\.') AS label
  FROM authorization_codes c, p
  WHERE c.oidc_nonce LIKE 'bal033v1.' || p.op || '.%'
), families AS (
  SELECT c.label, c.session_id AS code_session, c.client_id AS code_client,
         c.resource AS code_resource, c.consumed_at AS code_consumed,
         c.oidc_nonce, f.id,f.session_id,f.client_id,f.resource,f.expires_at,f.revoked_at
  FROM codes c JOIN refresh_families f ON f.source_code_id=c.id
), challenges AS (
  SELECT l.id,l.session_id,l.client_id,l.post_logout_redirect_uri,
         l.downstream_state,l.consumed_at FROM logout_challenges l, p
  WHERE l.downstream_state LIKE p.op || '%'
), matches AS (
  SELECT a.id AS a_id, b.id AS b_id, a.revoked_at AS a_revoked,
         b.revoked_at AS b_revoked, s.revoked_at AS session_revoked,
         l.consumed_at AS logout_consumed,
         a.expires_at AS a_expires, b.expires_at AS b_expires,
         s.expires_at AS session_expires,
         a.oidc_nonce AS a_nonce, b.oidc_nonce AS b_nonce,
         l.downstream_state AS logout_state,
         a.code_consumed AS a_code_consumed, b.code_consumed AS b_code_consumed
  FROM families a JOIN families b ON a.label='A' AND b.label='B'
    AND a.id<>b.id AND a.session_id=b.session_id
    AND a.code_session=a.session_id AND b.code_session=b.session_id
  JOIN provider_sessions s ON s.id=a.session_id
  JOIN challenges l ON l.session_id=s.id
  WHERE a.client_id='balance-mobile-staging' AND b.client_id=a.client_id
    AND a.code_client=a.client_id AND b.code_client=b.client_id
    AND l.client_id=a.client_id
    AND a.resource='https://balance-staging.shocker.cl/api'
    AND b.resource=a.resource AND a.code_resource=a.resource
    AND b.code_resource=b.resource
    AND l.post_logout_redirect_uri='balance-dev://logout-callback'
), evidence AS (
  SELECT COALESCE((SELECT true FROM p),false) AS valid_reference,
    (SELECT count(*) FROM codes) AS code_count,
    (SELECT count(*) FROM families WHERE label='A') AS a_count,
    (SELECT count(*) FROM families WHERE label='B') AS b_count,
    (SELECT count(*) FROM challenges) AS challenge_count,
    (SELECT count(*) FROM matches) AS same_session_count,
    COALESCE((SELECT bool_and(
      a_nonce ~ ('^bal033v1\.' || p.op || '\.A\.[a-f0-9]{32}$')
      AND b_nonce ~ ('^bal033v1\.' || p.op || '\.B\.[a-f0-9]{32}$')
      AND logout_state ~ ('^' || p.op || '[a-f0-9]{32}$')
      AND a_code_consumed IS NOT NULL AND b_code_consumed IS NOT NULL
      AND a_code_consumed < logout_consumed AND b_code_consumed < logout_consumed
      AND a_revoked < logout_consumed
      AND b_revoked=logout_consumed AND session_revoked=logout_consumed
      AND a_expires>logout_consumed AND b_expires>logout_consumed
      AND session_expires>logout_consumed
      -- Captured after the client probe: expiry cannot explain its rejection.
      AND b_expires>p.proof_at AND session_expires>p.proof_at
      AND EXISTS (SELECT 1 FROM refresh_token_members m
        JOIN refresh_token_members n ON n.id=m.successor_id AND n.family_id=m.family_id
        WHERE m.family_id=a_id AND m.consumed_at<logout_consumed
          AND n.issued_at<=logout_consumed)
      AND EXISTS (SELECT 1 FROM refresh_token_members m
        JOIN refresh_token_members n ON n.id=m.successor_id AND n.family_id=m.family_id
        WHERE m.family_id=b_id AND m.consumed_at<logout_consumed
          AND n.issued_at<=logout_consumed)
    ) FROM matches,p),false) AS lifecycle_matches
)
SELECT json_build_object(
  'valid_reference',valid_reference,'code_count',code_count,
  'a_count',a_count,'b_count',b_count,'challenge_count',challenge_count,
  'same_session_count',same_session_count,'lifecycle_matches',lifecycle_matches,
  'provider_evidence_complete',valid_reference AND code_count=2 AND a_count=1
    AND b_count=1 AND challenge_count=1 AND same_session_count=1 AND lifecycle_matches
) FROM evidence;
ROLLBACK;
