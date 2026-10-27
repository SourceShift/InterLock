# Secret files for the cloud stack

Every file in this directory other than this README is ignored by git. Nothing
here is generated for you: the *operator* creates each file on the host with
mode `0600` and mounts it through the compose `secrets:` block. Do not put a
secret in `.env` - the compose profile reads `*_FILE` paths precisely so a
secret never appears in `docker inspect`.

| File | Content |
| --- | --- |
| `postgres-password` | the password for the `interlock` Postgres role |
| `session-secret` | at least 32 random characters, for session cookies |
| `approval-key` | 32 bytes of hex: the Ed25519 *approval* seed (C3) |
| `policy-key` | 32 bytes of hex: a distinct Ed25519 *policy* seed (C5) |
| `preview-kek` | hex or base64 key-encryption key for preview/secret sealing |
| `oidc-client-secret` | the OIDC client secret (may be empty when OIDC is off) |

Generate key material on the host, never in a shell history that is shared:

```bash
install -d -m 0700 deploy/cloud/secrets
umask 077
printf '%s' "$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
  > deploy/cloud/secrets/approval-key
printf '%s' "$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
  > deploy/cloud/secrets/policy-key
printf '%s' "$(python3 -c 'import secrets;print(secrets.token_hex(32))')" \
  > deploy/cloud/secrets/preview-kek
printf '%s' "$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  > deploy/cloud/secrets/session-secret
```

The approval and policy seeds must be *different*: a manifest signature must
never be interchangeable with a grant signature. Both are read at use time and
never written to the database or a log.
