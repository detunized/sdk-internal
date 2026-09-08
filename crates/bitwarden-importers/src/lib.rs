#![doc = include_str!("../README.md")]

use bitwarden_collections::collection::CollectionId;
use bitwarden_core::OrganizationId;
use bitwarden_vault::{CipherType as VaultCipherType, FolderId};

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod error;
pub use error::ImportError;
mod import;
mod importer_client;
pub use importer_client::{ImporterClient, ImporterClientExt};
mod importers;
pub(crate) use importers::keeper;
use importers::onepassword::access::{Credentials, SignInAddress, SignInDomain};
/// The two-factor callback [`ImporterClient::import_onepassword`] drives, and what it answers
/// with.
pub use importers::onepassword::access::{
    TotpResult as OnePasswordTotpResult, TwoFactorUi as OnePasswordTwoFactorUi,
    generate_device_uuid,
};
mod pipeline;

/// The 1Password access module: log in to an account and download its vaults.
///
/// Exposed only under the `test-utils` feature, for the out-of-tree CLI that drives it against
/// a real account. Not part of this crate's supported API, and no stability is promised.
// TODO: Remove once the importer consumes the module directly.
#[cfg(feature = "test-utils")]
pub use importers::onepassword::access as onepassword_access;
/// The 1Password conversion step: downloaded vaults to the [`ParsedImport`] the pipeline
/// submits.
///
/// Exposed only under the `test-utils` feature, so the CLI can print what a real account
/// converts to. Not part of this crate's supported API, and no stability is promised.
// TODO: Remove once the importer consumes the module directly.
#[cfg(feature = "test-utils")]
pub use importers::onepassword::convert as onepassword_convert;
#[cfg(feature = "test-utils")]
pub use pipeline::ParsedImport;

/// Destination options for a vault import.
///
/// `organization_id` selects the destination: `None` imports into the user's personal vault (groups
/// become personal folders), `Some` imports into that organization (ciphers are encrypted with the
/// org key). `target_folder` (personal) and `target_collection` (organization) nest the import
/// under an existing destination, mirroring the client's import-target behavior; each carries both
/// its id and name together so a half-specified target can't be expressed. `restricted_types` are
/// dropped before submission.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
pub struct ImportOptions {
    pub organization_id: Option<OrganizationId>,
    pub target_folder: Option<ImportTargetFolder>,
    pub target_collection: Option<ImportTargetCollection>,
    // `VaultCipherType` is the wasm-bindgen enum exported as `CipherType`; pin the TS name so
    // tsify doesn't emit the Rust alias.
    #[cfg_attr(feature = "wasm", tsify(type = "CipherType[]"))]
    pub restricted_types: Vec<VaultCipherType>,
}

/// An existing personal folder to nest a personal import under.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
pub struct ImportTargetFolder {
    pub id: FolderId,
    pub name: String,
}

/// An existing organization collection to assign an org import to.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
pub struct ImportTargetCollection {
    pub id: CollectionId,
    pub name: String,
}

/// Counts of what an import submitted to the server, broken down by cipher type so the client can
/// render its per-type result table.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(into_wasm_abi)
)]
pub struct ImportSummary {
    pub ciphers: Vec<CipherTypeCount>,
    pub folders: u32,
    pub collections: u32,
}

/// Number of imported ciphers of a given type.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(into_wasm_abi)
)]
pub struct CipherTypeCount {
    #[cfg_attr(feature = "wasm", tsify(type = "CipherType"))]
    pub r#type: VaultCipherType,
    pub count: u32,
}

/// A 1Password account to import from, as a client collects it from a sign-in form.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
pub struct OnePasswordAccount {
    /// The account's email address.
    pub email: String,
    /// The account's master password.
    pub password: String,
    /// The account's Secret Key, such as `A3-XXXXXX-...`.
    pub secret_key: String,
    /// The account's sign-in subdomain: the `my` of `my.1password.com`.
    pub sign_in_subdomain: String,
    /// Which 1Password region hosts the account.
    pub region: OnePasswordRegion,
    /// A device id to reuse. Absent generates a fresh one, which is what a one-shot import wants.
    pub device_uuid: Option<String>,
}

/// Where a 1Password account's data is hosted.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
pub enum OnePasswordRegion {
    /// `1password.com`, the default.
    Global,
    /// `1password.eu`.
    Europe,
    /// `1password.ca`.
    Canada,
    /// `ent.1password.com`, for 1Password Enterprise.
    Enterprise,
}

impl From<&OnePasswordRegion> for SignInDomain {
    fn from(region: &OnePasswordRegion) -> Self {
        match region {
            OnePasswordRegion::Global => SignInDomain::Global,
            OnePasswordRegion::Europe => SignInDomain::Europe,
            OnePasswordRegion::Canada => SignInDomain::Canada,
            OnePasswordRegion::Enterprise => SignInDomain::Enterprise,
        }
    }
}

impl TryFrom<OnePasswordAccount> for Credentials {
    type Error = ImportError;

    fn try_from(account: OnePasswordAccount) -> Result<Self, ImportError> {
        let sign_in_address =
            SignInAddress::new(&account.sign_in_subdomain, (&account.region).into())?;

        Ok(Credentials {
            username: account.email,
            password: account.password,
            account_key: account.secret_key,
            sign_in_address,
            device_uuid: account.device_uuid.unwrap_or_else(generate_device_uuid),
        })
    }
}
