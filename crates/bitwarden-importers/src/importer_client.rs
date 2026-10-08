use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Credentials, ImportError, ImportOptions, ImportSummary, OnePasswordImportSummary,
    OnePasswordSecureStorage, OnePasswordSsoCredentials, OnePasswordSsoUi, OnePasswordTwoFactorUi,
    import::{import_kdbx, import_onepassword, import_onepassword_sso},
    importers::onepassword::access,
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ImporterClient {
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ImporterClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    /// Import a KeePass KDBX (`.kdbx`) database and submit it to the server.
    ///
    /// Parses and decrypts the raw `.kdbx` bytes (unlocked with the password and/or key file),
    /// encrypts the entries for the user's personal vault or the given organization, and submits
    /// them to the import endpoint. Returns the counts of what was imported. Inputs larger than
    /// 10 MiB are rejected with `KdbxFileTooLarge`.
    pub async fn import_kdbx(
        &self,
        file: Vec<u8>,
        password: Option<String>,
        key_file: Option<Vec<u8>>,
        options: ImportOptions,
    ) -> Result<ImportSummary, ImportError> {
        import_kdbx(&self.client, file, password, key_file, options).await
    }

    /// Generates a device id for [`ImporterClient::import_onepassword_sso`].
    ///
    /// The account knows a device by that id, so persist it next to the secure storage and pass
    /// the same one on every import; a fresh id each time undoes the enrollment and repeats the
    /// device approval.
    pub fn generate_onepassword_device_uuid(&self) -> String {
        access::generate_device_uuid()
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl ImporterClient {
    /// The same import as [`ImporterClient::import_onepassword`], for JavaScript, which passes the
    /// two-factor prompt as an object rather than a `&dyn` callback.
    #[wasm_bindgen(js_name = import_onepassword)]
    pub async fn import_onepassword_wasm(
        &self,
        credentials: Credentials,
        two_factor: crate::wasm::RawJsOnePasswordTwoFactorUi,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary, ImportError> {
        let two_factor = crate::wasm::JsOnePasswordTwoFactorUi::new(two_factor);
        import_onepassword(&self.client, credentials, &two_factor, options).await
    }

    /// The same import as [`ImporterClient::import_onepassword_sso`], for JavaScript, which passes
    /// the callbacks as objects rather than `&dyn` references.
    #[wasm_bindgen(js_name = import_onepassword_sso)]
    pub async fn import_onepassword_sso_wasm(
        &self,
        credentials: OnePasswordSsoCredentials,
        ui: crate::wasm::RawJsOnePasswordSsoUi,
        storage: crate::wasm::RawJsOnePasswordSecureStorage,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary, ImportError> {
        let ui = crate::wasm::JsOnePasswordSsoUi::new(ui);
        let storage = crate::wasm::JsOnePasswordSecureStorage::new(storage);
        import_onepassword_sso(&self.client, credentials, &ui, &storage, options).await
    }
}

// Separate from the block above: `wasm_bindgen` cannot export the `&dyn` callbacks.
impl ImporterClient {
    /// Import a 1Password account directly from the 1Password servers.
    ///
    /// Signs in with the email, master password and Secret Key in `credentials`, asking
    /// `two_factor` for a code when the account requires one, downloads and decrypts every vault
    /// the account can open, and submits the result to the import endpoint. Each vault becomes a
    /// folder. Returns the imported counts plus any vaults or items that could not be imported.
    pub async fn import_onepassword(
        &self,
        credentials: Credentials,
        two_factor: &dyn OnePasswordTwoFactorUi,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary, ImportError> {
        import_onepassword(&self.client, credentials, two_factor, options).await
    }

    /// The same import as [`ImporterClient::import_onepassword`], signing in with single sign-on.
    ///
    /// Signs in with the email, device id and sign-in address in `credentials` through the
    /// account's identity provider, which `ui` opens for the user. On a device the account does
    /// not trust yet, the user approves this device from another 1Password device and types the
    /// verification code it shows, again through `ui`. `storage` keeps what reopens the
    /// credentials that approval hands over, so a later import with the same device id and storage
    /// can skip it. A sign-in the user gives up on, at the identity provider or during the
    /// approval, ends with `ImportError::OnePasswordCanceled`.
    pub async fn import_onepassword_sso(
        &self,
        credentials: OnePasswordSsoCredentials,
        ui: &dyn OnePasswordSsoUi,
        storage: &dyn OnePasswordSecureStorage,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary, ImportError> {
        import_onepassword_sso(&self.client, credentials, ui, storage, options).await
    }
}

#[allow(missing_docs)]
pub trait ImporterClientExt {
    fn importers(&self) -> ImporterClient;
}

impl ImporterClientExt for Client {
    fn importers(&self) -> ImporterClient {
        ImporterClient::new(self.clone())
    }
}
