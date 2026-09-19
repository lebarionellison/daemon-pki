# Daemon PKI cryptographic and certificate policies

## Default policy

- Short-lived certificates by default.
- Explicit SAN requirements.
- Explicit EKU requirements.
- No implicit trust.
- Every issuance request is authenticated.
- Every issuance request is authorized.
- Every signing operation is policy evaluated.
- Private CA keys are never returned through the API.
- Root CA keys remain offline/protected whenever possible.
- All security-sensitive operations generate audit events.

## Algorithm policy

The implementation will use modern, maintained cryptographic
primitives and will reject deprecated or explicitly prohibited
algorithms according to policy.

Algorithm support must be versioned and centrally policy-controlled.
