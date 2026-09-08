# Importer review

The review as received. Its test results are the reviewer's and have not been rerun.

All 171 importer tests and the UniFFI/WASM compile checks pass, but uncovered cases produce unusable
SSH keys, silently incomplete imports, lost URLs, incorrect dates, and missing functional TOTP
mappings.

Full review comments:

- [P1] Normalize SSH private keys to OpenSSH before importing —
  /Users/detunized/devel/bitwarden/sdk-internal/crates/bitwarden-importers/src/importers/onepassword/convert.rs:462-466
  For 1Password SSH items containing PKCS#8 keys, this copies `-----BEGIN PRIVATE KEY-----` directly
  into the cipher. Bitwarden’s SSH agent and `bitwarden_ssh::export_pkcs8_der_key` parse only
  OpenSSH, so these imported keys cannot be used by the agent or exported through Credential
  Exchange. Convert through `bitwarden_ssh::import::import_key` and use its normalized key material,
  as the existing CXF importer does.

- [P1] Surface skipped items in the public import result —
  /Users/detunized/devel/bitwarden/sdk-internal/crates/bitwarden-importers/src/import.rs:40-40 When
  an item cannot be decrypted or parsed, the access layer now records it in `Vault::skipped` and
  continues, but conversion discards that information. This call consequently returns ordinary
  success counts without letting Rust, WASM, or UniFFI callers distinguish a complete migration from
  a partial one—even when every item was skipped. Carry skipped-item diagnostics through the
  conversion and result types so callers can warn users about missing data.

- [P2] Preserve website URLs when converting Password items —
  /Users/detunized/devel/bitwarden/sdk-internal/crates/bitwarden-importers/src/importers/onepassword/convert.rs:309-310
  A 1Password Password-category item can have website addresses in its overview, but this mapper
  never receives the overview and always creates an empty URI list. Those addresses are not
  preserved as custom fields either, so the imported login loses its website and cannot match it for
  autofill. Reuse the overview URL mapping and sanitization already used by the other
  login-producing categories.

- [P2] Avoid silently shifting dates with a fixed UTC offset —
  /Users/detunized/devel/bitwarden/sdk-internal/crates/bitwarden-importers/src/importers/onepassword/convert.rs:671-675
  For dates written at midnight in UTC+13 or UTC+14, adding twelve hours still produces the previous
  calendar day. For example, `1772535600` represents March 4, 2026 at midnight in New Zealand, but
  this function imports `2026-03-03`, corrupting birth and expiration dates. Use explicit timezone
  context or preserve the original timestamp when the intended date is ambiguous; a fixed offset
  cannot recover every source timezone.

- [P2] Select the first populated TOTP field —
  /Users/detunized/devel/bitwarden/sdk-internal/crates/bitwarden-importers/src/importers/onepassword/convert.rs:508-512
  If an item has an empty or valueless `TOTP_` field before a populated one, `find` stops at the
  empty field and the subsequent `and_then` returns `None`. The usable secret becomes only a hidden
  custom field, leaving the imported login unable to generate verification codes. Include value
  validation in the search, such as with `find_map`, so empty template fields do not prevent
  selecting a usable TOTP.
