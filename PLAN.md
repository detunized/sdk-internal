# 1Password importer, phase 2: convert and import

Phase 1 (PR #1371, branch `onepassword-access`) delivers the `access` module: log in with password +
Secret Key + TOTP, download and decrypt every vault. It stops at
`Client::download_all_vaults() -> Vec<Vault>`, where each `Item` holds the decrypted
`VaultItemOverview` and `VaultItemDetails` exactly as 1Password sends them.

Phase 2 makes that data importable: map the decrypted wire shapes to `ImportingCipher`, feed the
existing `pipeline::submit_import`, and expose one public method on `ImporterClient` with a 2FA
callback bridged over wasm and uniffi.

## Decisions already made (from the phase 1 sessions and PR review)

- **No intermediate model.** Map `overview`/`details` straight to `ImportingCipher`, like
  `importers/kdbx.rs` does. The old native model was deleted from the access PR ("Drop the native
  model parsing") precisely because an intermediate that mirrors `CipherType` earns nothing and is
  where data loss lived.
- **1Password quirks live in helper functions, not structs**: TOTP is a section field with
  `k == "concealed"` and `n` starting `TOTP_`; SSH key material is in `a.sshKeyAttributes`, never in
  `v`; a Password item carries its secret in `details.password`, not in `fields`; always match on
  the stable id `n`, never the localized label `t`.
- **Consume-once, leftovers survive.** Known field ids fill typed cipher slots and are consumed;
  every unclaimed field becomes a custom `Field` (concealed -> hidden type 1, everything else ->
  text type 0). Nothing is dropped by construction. Real vaults contain 1P-injected sections with
  random ids and empty titles, so the leftover branch is the default path, not an afterthought.
- **Passport / BankAccount / DriversLicense import as SecureNote + custom fields** for now.
  `bitwarden_exporters::CipherType` has payload-less variants for them and the
  `From<ImportingCipher> for CipherView` bridge hardcodes their payloads to `None`. Extending
  `ImportingCipher` upstream is a follow-up, not part of this phase.
- **Password history is out of scope.** `ImportingCipher` cannot carry it
  (`bitwarden-exporters/src/lib.rs` drops it in the bridge). Follow-up upstream change, including
  the `MAX_PASSWORD_HISTORY_ENTRIES = 5` cap question.
- **1P has no folders.** Vaults are the only container; tags are multi-valued and have no Bitwarden
  equivalent. See open question 1 for what vaults map to.

## New code

```
crates/bitwarden-importers/src/importers/onepassword/
  mod.rs        gains the orchestration: login -> download -> convert -> submit
  convert.rs    NEW: Vec<access::model::Vault> -> ParsedImport
```

Wiring edits, mirroring KDBX:

- `import.rs`: `import_onepassword(client, credentials, ui, options)` route.
- `importer_client.rs`:
  `pub async fn import_onepassword(...) -> Result<ImportSummary, ImportError>`.
- `error.rs`: 1Password variants on the flat `ImportError` (see Error mapping).
- `bitwarden-uniffi/src/tool/mod.rs` and `bitwarden-wasm-internal`: the new method plus the 2FA
  callback type. No new sub-client.

Orchestration sketch (destination only, no local stubs anymore):

```rust
pub(crate) async fn import_onepassword(
    client: &Client,
    credentials: Credentials,
    ui: Arc<dyn TwoFactorUi>,
    options: ImportOptions,
) -> Result<ImportSummary, ImportError> {
    let op = access::Client::new(client.internal.get_http_client().clone());
    let vaults = op.download_all_vaults(&credentials, ui.as_ref()).await?;
    let parsed = convert::convert(vaults);
    pipeline::submit_import(client, parsed, options).await
}
```

## convert.rs design

Input `Vec<Vault>`, output `ParsedImport { ciphers, folders, folder_relationships }`.

Universal rules, applied to every item before category dispatch:

| Target       | Source                                                          |
| ------------ | --------------------------------------------------------------- |
| `name`       | `overview.title`, `"--"` when empty (KDBX convention)           |
| `notes`      | `details.note`                                                  |
| `login_uris` | `overview.url` + `overview.urls[]`, then `Login::sanitize_uris` |
| `login.totp` | first TOTP section field; extra TOTPs stay custom fields        |
| `fields`     | every unconsumed section field and designation field            |
| `favorite`   | not on the wire today (see access additions)                    |
| dates        | not on the wire today (see access additions)                    |
| tags         | joined into a custom field `tags` so they survive               |

Category dispatch on `ItemCategory` (template id):

| 1P category                                                       | CipherType   | Consumed fields                                                   |
| ----------------------------------------------------------------- | ------------ | ----------------------------------------------------------------- |
| Login                                                             | `Login`      | `details.fields` by `designation` (username/password), TOTP       |
| Password                                                          | `Login`      | `details.password`; no username                                   |
| Server, EmailAccount, ApiCredential, Database, WirelessRouter     | `Login`      | username/password/hostname ids per category table                 |
| CreditCard                                                        | `Card`       | `cardholder`, `ccnum`, `cvv`, `expiry` (monthYear int), `type`    |
| Identity                                                          | `Identity`   | `firstname`, `lastname`, `address` (object), `email`, phones, ... |
| SecureNote                                                        | `SecureNote` | none, note only                                                   |
| SshKey                                                            | `SshKey`     | `a.sshKeyAttributes` (private/public/fingerprint)                 |
| everything else, incl. Passport/BankAccount/DriverLicense/Unknown | `SecureNote` | none, all fields become custom                                    |

The per-category id tables are the only 1P knowledge the mapper needs. Verify each id against a real
dump before writing it down (the C# reference and the July plan have candidate lists, but real data
is the source of truth; the access CLI dump provides it).

Value rendering, decided once in one helper:

- string `v` passes through; missing `v` stays `None`, not `""`.
- `monthYear` ints like `202112` render as `2021-12` for card expiry (split into `exp_month` /
  `exp_year` on Card, formatted text elsewhere).
- unix `date` ints render as `YYYY-MM-DD`.
- the `address` object flattens into Identity slots when consumed; as a leftover it flattens into
  one custom field per sub-key (`street`, `city`, `zip`, ...).
- any other non-string `v` serializes to compact JSON text.

Field type: hidden (1) when `k == "concealed"` or `a.guarded == "yes"`, text (0) otherwise.

## Error mapping

`ImportError` is `#[bitwarden_error(flat)]`, so each variant is a distinct code the UI can switch
on. Add mapped variants rather than one transparent wrapper:

- `OnePasswordBadCredentials`
- `OnePasswordTwoFactorRequired` / `OnePasswordTwoFactorFailed`
- `OnePasswordUnsupported` (unsupported 2FA method, unsupported login method)
- `OnePasswordNetwork`
- `OnePasswordDecryption`

Implemented as a manual `From<OnePasswordError> for ImportError` in the onepassword module, keeping
`error.rs` free of 1P knowledge beyond the variants.

## 2FA callback bridge

Layer boundary stays: `access::TwoFactorUi` is the Rust trait, bindings adapt to it.

- **uniffi**: `#[uniffi::export(with_foreign)]` callback interface with
  `provide_totp(attempt: u32) -> TotpResult`; precedent in
  `bitwarden-uniffi/src/platform/repository.rs` and `log_callback.rs`.
- **wasm**: a JS-implemented interface wrapped in `ThreadBoundRunner` for the `!Send` JS handle;
  precedent in `bitwarden-wasm-internal/src/platform/token_provider.rs`. Never `async_trait(?Send)`
  in hand-written code (repo rule).
- Browser CORS still blocks direct calls to `*.1password.com`, so the importer is native-first
  (desktop/mobile). The wasm binding ships for API parity; document that.

## Access module changes this phase needs

Small, contained additions, each its own commit on top of the access PR:

1. `VaultItem` wire type gains `createdAt` / `updatedAt` (1P sends them); `Item` carries them
   through so `creation_date` / `revision_date` are real instead of `Utc::now()`. Same for
   `favorite` if the wire carries it (verify against a real dump).
2. Per-item decrypt failure policy: today one undecryptable item aborts the whole download (README
   TODO). For an importer, record and skip: collect per-item errors, surface counts in the result
   instead of failing the account. Decide the shape (probably `Vec<SkippedItem>` alongside the
   vaults or on `Vault`).
3. Once `import_onepassword` consumes the module: drop `#[allow(dead_code, unused_imports)]`, make
   `access` `pub(crate)`, and remove the `test-utils` re-export, provided the out-of-tree CLI is
   retired or repointed (open question 2).

## Testing

1. **Conversion unit tests** in `convert.rs`: one native item per implemented category, assert the
   resulting `ImportingCipher` (type, slots, custom fields, folder links). Build items from
   decrypted JSON fixtures; `vault-item-with-lots-of-fields.json` already exists, add one fixture
   per category from a sanitized real dump.
2. **Leftover discipline test**: an item with unknown section ids, missing `v`, object `v`, and a
   guarded field; assert nothing is lost and types are right.
3. **End-to-end**: real-account verification through the CLI (login, download, convert, print), the
   same way phase 1 was validated. Optional wiremock flow test only if the orchestration grows logic
   beyond glue.

## Open questions (decide before or during implementation)

1. **Vault -> folder or collection.** The access README (from itsadrago's review comment) says
   vaults become collections, but `ParsedImport` expresses only folder paths, and the pipeline's
   collection support is a single target collection for organization imports. Recommendation: map
   vault name -> folder for personal imports now (works today, nests under `target_folder`
   automatically) and treat per-vault collections as a pipeline extension follow-up. Update the
   README if accepted.
2. **CLI future.** The out-of-tree CLI drives access via the `test-utils` re-export. Either extend
   the re-export so the CLI can also print `ParsedImport` (keeps real-account verification of the
   mapper, delays the `pub(crate)` cleanup), or retire the CLI once conversion tests cover the
   mapper. Recommendation: extend first, retire after the phase 2 PR merges.
3. **Document category.** Attachments/documents cannot be imported; decide between SecureNote with
   an explanatory note per item vs skipping with a recorded warning. Recommendation: SecureNote +
   note, nothing silently disappears.
4. **Where 2FA state lives in the UI flow.** One-shot import only (no remember-me token), confirmed
   in phase 1; re-confirm with the clients team when the UI lands.

## Build order (small, reviewable commits)

All nine steps have landed on `onepassword-convert`.

1. [x] `convert.rs` skeleton: vault -> folder, universal rules, Login category, tests.
2. [x] Value rendering helper + leftover discipline, tests.
3. [x] Card, Identity, SshKey categories, tests.
4. [x] Password, Server-family categories, tests.
5. [x] Fallback categories (SecureNote + custom fields), tests.
6. [x] Access additions: item dates, skip-and-record decrypt policy. Favorite is not on the wire.
7. [x] Orchestration `import_onepassword` + `ImportError` variants + routing.
8. [x] uniffi + wasm bindings with the TwoFactorUi bridge.
9. [x] Cleanup: per-field `allow(dead_code)` with reasons, README updates. The `test-utils`
       re-export stays until the out-of-tree CLI is retired.

What the real account taught us, against what this plan assumed:

- `a.guarded` is not a secrecy marker: the identity template sets it on plain fields such as the
  first name. Only `k` decides, with `sshKey` folded in beside `concealed`.
- SSH key material is in `a.sshKeyAttributes`; the public key and fingerprint are only there.
- 1Password writes a `date` as midnight in the writer's own zone and never records which, so the
  stamp is read at noon to land on the day that was meant.
- A `file` field's value is the envelope that unwraps the stored file, encryption keys included.
  Only the name survives.
- `favorite` is not in the items response, though 1Password's own CLI reports it.

Phase 2 lands as its own PR on top of the access PR, as promised in the PR #1371 description ("The
next PR will provide the 2nd layer that converts from the result of `download_all_vaults` to the
Bitwarden internal data types and imports it").
