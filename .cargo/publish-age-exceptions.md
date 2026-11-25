# Publish-age exceptions

Cargo 1.100 does not support package-specific publish-age exceptions. A recent
version already recorded in `Cargo.lock` is permitted even while
`resolver.incompatible-publish-age = "deny"` is active. The entries below
preserve the exceptions previously reviewed for this repository.

To intentionally admit one of these versions into the lockfile, use a narrowly
targeted update while temporarily allowing recent versions:

```sh
cargo update -p <crate> --precise <version> --config 'resolver.incompatible-publish-age="allow"'
```

Review the complete `Cargo.lock` diff before committing it. The temporary
`allow` setting applies to the whole resolution operation, including transitive
dependencies. Normal builds and CI should continue using `--locked`.

If `Cargo.lock` is deleted, these documented exceptions are not applied
automatically and must be reviewed and admitted again.

## Previously reviewed exceptions

```toml
[[allow.exact]]
crate = "chacha20"
version = "0.10.2"

[[allow.exact]]
crate = "bollard"
version = "0.21.1"

[[allow.exact]]
crate = "rustls"
version = "0.23.46"

# Security fixes for RUSTSEC-2026-0382, RUSTSEC-2026-0383,
# RUSTSEC-2026-0385, and RUSTSEC-2026-0410.
# Same reviewed exceptions as union-bridge-client (2026-10-26): registry
# publisher/checksum and packaged sources match the tagged upstream commit
# (zstd-sys: vendored zstd is upstream v1.5.7); keep the exceptions limited
# to these versions.
# https://github.com/RustCrypto/utils/releases/tag/ctutils-v0.4.6
# https://github.com/rustls/webpki/releases/tag/v%2F0.103.16
# https://github.com/rustls/webpki-roots/releases/tag/v%2F1.0.11
# https://github.com/gyscos/zstd-rs/releases/tag/zstd-sys-2.1.2
[[allow.exact]]
crate = "ctutils"
version = "0.4.6"

[[allow.exact]]
crate = "rustls-webpki"
version = "0.103.16"

[[allow.exact]]
crate = "webpki-root-certs"
version = "1.0.11"

[[allow.exact]]
crate = "zstd-sys"
version = "2.1.2+zstd.1.5.7"

# Security fix for RUSTSEC-2026-0418; keep the exception limited to this version.
# https://rustsec.org/advisories/RUSTSEC-2026-0418
# https://github.com/rust-lang/libz-sys/pull/280
[[allow.exact]]
crate = "libz-sys"
version = "1.1.31"

# Security fix for RUSTSEC-2026-0592. url 2.5.9 requires
# form_urlencoded ^1.2.3, so both recent versions are admitted together.
# https://rustsec.org/advisories/RUSTSEC-2026-0592
[[allow.exact]]
crate = "url"
version = "2.5.9"

[[allow.exact]]
crate = "form_urlencoded"
version = "1.2.3"
```
