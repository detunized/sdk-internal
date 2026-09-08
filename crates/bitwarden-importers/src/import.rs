//! Routing: maps each importer's public entry to its parser + the generic submit pipeline.

use std::sync::Arc;

use bitwarden_core::Client;

use crate::{
    ImportError, ImportOptions, ImportSummary, OnePasswordTwoFactorUi,
    importers::{self, onepassword::convert},
    pipeline,
};

/// See [crate::ImporterClient::import_kdbx] for more documentation.
pub(crate) async fn import_kdbx(
    client: &Client,
    file: Vec<u8>,
    password: Option<String>,
    key_file: Option<Vec<u8>>,
    options: ImportOptions,
) -> Result<ImportSummary, ImportError> {
    let parsed = importers::kdbx::parse(file, password, key_file)?;
    pipeline::submit_import(client, parsed, options).await
}

/// See [crate::ImporterClient::import_onepassword] for more documentation.
pub(crate) async fn import_onepassword(
    client: &Client,
    credentials: crate::importers::onepassword::access::Credentials,
    ui: Arc<dyn OnePasswordTwoFactorUi>,
    options: ImportOptions,
) -> Result<ImportSummary, ImportError> {
    // 1Password is a third-party host, so this rides the client's external transport rather than
    // the one configured for the Bitwarden API.
    let onepassword =
        importers::onepassword::access::Client::new(client.internal.get_http_client().clone());
    let vaults = onepassword
        .download_all_vaults(&credentials, ui.as_ref())
        .await?;

    pipeline::submit_import(client, convert::convert(vaults), options).await
}
