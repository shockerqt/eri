ALTER TABLE browser_authorizations
    DROP CONSTRAINT browser_authorizations_stage_check;
ALTER TABLE browser_authorizations
    ADD CONSTRAINT browser_authorizations_stage_check
    CHECK (stage IN ('awaiting_start','awaiting_google','callback_claimed','awaiting_consent','approved','denied','failed','expired'));
