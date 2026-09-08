//! Bridges the 1Password two-factor prompt to a JavaScript implementation.
//!
//! Browsers block cross-origin calls to 1Password, so an import cannot actually run in one. The
//! binding exists so the TypeScript surface matches the other platforms.

use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use super::access::{TotpResult, TwoFactorUi};

#[wasm_bindgen(typescript_custom_section)]
const ONEPASSWORD_TWO_FACTOR_PROMPT: &'static str = r#"
export interface OnePasswordTwoFactorPrompt {
    /// Returns the code the user entered, or undefined if they cancelled. Each rejected code
    /// restarts the login, so `attempt` grows as the user retries.
    provide_totp(attempt: number): Promise<string | undefined>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = OnePasswordTwoFactorPrompt)]
    pub type JsOnePasswordTwoFactorPrompt;

    #[wasm_bindgen(method)]
    pub async fn provide_totp(this: &JsOnePasswordTwoFactorPrompt, attempt: u32) -> JsValue;
}

/// Holds the JavaScript prompt on the thread that owns it, so the importer can drive it from a
/// `Send` context.
pub(crate) struct WasmTwoFactorPrompt(ThreadBoundRunner<JsOnePasswordTwoFactorPrompt>);

impl WasmTwoFactorPrompt {
    pub(crate) fn new(prompt: JsOnePasswordTwoFactorPrompt) -> Self {
        Self(ThreadBoundRunner::new(prompt))
    }
}

#[async_trait::async_trait]
impl TwoFactorUi for WasmTwoFactorPrompt {
    async fn provide_totp(&self, attempt: u32) -> TotpResult {
        let code = self
            .0
            .run_in_thread(
                move |prompt| async move { prompt.provide_totp(attempt).await.as_string() },
            )
            .await
            .unwrap_or_default();

        // A prompt that returns nothing, or one that could not be reached at all, is the user
        // declining: neither can produce a code.
        match code {
            Some(code) => TotpResult::Code(code),
            None => TotpResult::Cancel,
        }
    }
}
