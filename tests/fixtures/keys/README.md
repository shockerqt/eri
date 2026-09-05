# Test-only RSA keys

These fixed 2048-bit keys are public test fixtures. They are intentionally
committed only to make signature, validation, and rotation tests reproducible.
They must never sign staging or production tokens. Tests copy private fixtures
to temporary files and explicitly apply mode `0600` on Unix; they do not depend
on Git preserving restrictive permission bits.
