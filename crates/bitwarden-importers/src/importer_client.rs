use std::sync::Arc;

use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    ImportError, ImportOptions, ImportSummary, OnePasswordAccount, OnePasswordTwoFactorUi,
    import::{import_kdbx, import_onepassword},
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
}

/// The 1Password import over wasm, taking a JavaScript prompt for the two-factor code.
///
/// Browsers block cross-origin calls to 1Password, so this cannot complete in one today. It exists
/// so the TypeScript surface matches the other platforms.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl ImporterClient {
    /// Import a 1Password account directly from the 1Password servers, prompting `two_factor`
    /// when the account asks for a code.
    #[wasm_bindgen(js_name = importOnePassword)]
    pub async fn import_onepassword_wasm(
        &self,
        account: OnePasswordAccount,
        two_factor: crate::importers::onepassword::wasm::JsOnePasswordTwoFactorPrompt,
        options: ImportOptions,
    ) -> Result<ImportSummary, ImportError> {
        let prompt =
            Arc::new(crate::importers::onepassword::wasm::WasmTwoFactorPrompt::new(two_factor));

        import_onepassword(&self.client, account.try_into()?, prompt, options).await
    }
}

/// The 1Password import is not part of the `wasm_bindgen` surface on other platforms: its
/// two-factor callback is a Rust trait object, which needs a binding of its own to reach
/// JavaScript.
impl ImporterClient {
    /// Import a 1Password account directly from the 1Password servers.
    ///
    /// Signs in with the email, master password and Secret Key in `credentials`, prompting `ui`
    /// for a two-factor code when the account asks for one, downloads and decrypts every vault the
    /// account can open, and submits the result to the import endpoint. Each vault becomes a
    /// folder. Returns the counts of what was imported.
    ///
    /// Browsers block direct calls to 1Password, so this is for the desktop and mobile clients.
    pub async fn import_onepassword(
        &self,
        account: OnePasswordAccount,
        ui: Arc<dyn OnePasswordTwoFactorUi>,
        options: ImportOptions,
    ) -> Result<ImportSummary, ImportError> {
        import_onepassword(&self.client, account.try_into()?, ui, options).await
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
