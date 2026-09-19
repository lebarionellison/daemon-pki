# Daemon PKI

Zero-Trust Identity & Certificate Lifecycle Platform.

Daemon PKI manages cryptographic identity for workloads, services, devices,
and humans.

Core capabilities:

- X.509 PKI
- Certificate lifecycle management
- Workload identity
- SPIFFE/SVID compatibility
- mTLS
- Automated renewal and rotation
- Certificate discovery
- Revocation
- CRL and OCSP
- Trust bundles
- Policy enforcement
- Zero-trust authorization
- Kubernetes identity
- Device identity
- Cryptographic inventory
- Audit
- Multi-tenancy
- ACME automation
- Federation

The certificate generator is the free entry point.

The lifecycle and machine-identity platform is the core product.

## Security model

Root CA private keys must never be stored in source control,
Cloudflare KV, D1, browser storage, or ordinary API responses.

Online signing should use an intermediate CA.

Production deployments should support hardware-backed or managed
key protection such as HSM/KMS.

## Status

Early development.
