//! WASM bindings for the direct 1Password import.
//!
//! The import calls back into the user mid sign-in: for a TOTP code, or for the single sign-on
//! browser step, device approval and secure storage. `wasm_bindgen` cannot express these as the
//! `&dyn` callbacks the native API takes. JavaScript passes objects implementing the interfaces
//! declared below instead, and the `Js*` types adapt them back to the traits.

use async_trait::async_trait;
use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::prelude::*;

use crate::{
    OnePasswordSecureStorage, OnePasswordSsoEnrollment, OnePasswordSsoEnrollmentResult,
    OnePasswordSsoEnrollmentStatus, OnePasswordSsoLoginResult, OnePasswordSsoUi,
    OnePasswordTotpResult, OnePasswordTwoFactorUi, OnePasswordVerificationCodeResult,
};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
/**
 * Asks the user for a 1Password two-step verification code during a direct import.
 */
export interface OnePasswordTwoFactorUi {
    /**
     * Provides a TOTP passcode for the given zero-based attempt. A wrong code restarts the
     * sign-in, so `attempt` grows as the user retries.
     *
     * @returns the passcode, or undefined if the user declined to provide one.
     */
    provideTotp(attempt: number): Promise<string | undefined>;
}

/**
 * Takes the user through a 1Password single sign-on login during a direct import.
 */
export interface OnePasswordSsoUi {
    /**
     * Opens `ssoLoginUrl`, usually in a browser, and waits for the identity provider to redirect
     * to `redirectTo`.
     *
     * @returns the full URL the identity provider redirected to, or undefined if the user gave up.
     */
    performSsoLogin(ssoLoginUrl: string, redirectTo: string): Promise<string | undefined>;

    /**
     * Shows the device enrollment UI. Called when this device is not trusted yet, or its stored
     * credentials no longer work.
     */
    beginSsoEnrollment(): Promise<OnePasswordSsoEnrollment>;
}

/**
 * A device enrollment in progress. `endEnrollment` is called exactly once when it ends.
 */
export interface OnePasswordSsoEnrollment {
    /**
     * Resolves when the user cancels the enrollment; a rejection counts as a cancellation. Keep it
     * pending while the enrollment runs, and settle it once `endEnrollment` is called so the
     * object can be released.
     */
    cancelled(): Promise<void>;

    /** Shows the stage the enrollment has reached. */
    updateStatus(status: OnePasswordSsoEnrollmentStatus, message: string): Promise<void>;

    /**
     * Asks for the verification code the approving device shows.
     *
     * @returns the code, or undefined if the user declined to provide one.
     */
    provideVerificationCode(): Promise<string | undefined>;

    /** Closes the enrollment UI. */
    endEnrollment(result: OnePasswordSsoEnrollmentResult): Promise<void>;
}

/**
 * Secure per-device storage for the credentials a single sign-on login keeps.
 *
 * One storage can serve several accounts, as each keeps its record under a name of its own. Treat
 * the names as opaque keys. A rejection fails the import. Reject with a string to say why, and keep
 * stored values out of it.
 */
export interface OnePasswordSecureStorage {
    /**
     * Rejects when the storage cannot be read. Resolving to undefined then would make the device
     * enroll again and overwrite a value that is still there.
     *
     * @returns the value stored under `name`, or undefined or null if there is none.
     */
    loadString(name: string): Promise<string | undefined | null>;

    /** Stores `value` under `name`, replacing any previous one. Rejects when it cannot. */
    storeString(name: string, value: string): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// The JavaScript object implementing the two-factor prompt.
    #[wasm_bindgen(js_name = OnePasswordTwoFactorUi, typescript_type = "OnePasswordTwoFactorUi")]
    pub type RawJsOnePasswordTwoFactorUi;

    #[wasm_bindgen(catch, method, structural, js_name = provideTotp)]
    async fn provide_totp(
        this: &RawJsOnePasswordTwoFactorUi,
        attempt: u32,
    ) -> Result<JsValue, JsValue>;
}

/// Adapts the JavaScript prompt to [`OnePasswordTwoFactorUi`].
///
/// The JS object is `!Send`, so it stays pinned to its own thread behind a [`ThreadBoundRunner`];
/// only the runner's channel handle crosses threads, which is what makes this `Send + Sync`.
pub(crate) struct JsOnePasswordTwoFactorUi(ThreadBoundRunner<RawJsOnePasswordTwoFactorUi>);

impl JsOnePasswordTwoFactorUi {
    pub(crate) fn new(ui: RawJsOnePasswordTwoFactorUi) -> Self {
        Self(ThreadBoundRunner::new(ui))
    }
}

#[async_trait::async_trait]
impl OnePasswordTwoFactorUi for JsOnePasswordTwoFactorUi {
    async fn provide_totp(&self, attempt: u32) -> OnePasswordTotpResult {
        let code = self
            .0
            .run_in_thread(move |ui| async move {
                ui.provide_totp(attempt)
                    .await
                    .ok()
                    .and_then(|code| code.as_string())
            })
            .await;

        // A value that isn't a string, a rejected promise, and a runner whose thread went away all
        // leave the sign-in without a code, which is what cancelling it means.
        match code {
            Ok(Some(code)) => OnePasswordTotpResult::Code(code),
            Ok(None) | Err(_) => OnePasswordTotpResult::Cancel,
        }
    }
}

#[wasm_bindgen]
extern "C" {
    /// The JavaScript object implementing the single sign-on prompts.
    #[wasm_bindgen(js_name = OnePasswordSsoUi, typescript_type = "OnePasswordSsoUi")]
    pub type RawJsOnePasswordSsoUi;

    #[wasm_bindgen(catch, method, structural, js_name = performSsoLogin)]
    async fn perform_sso_login(
        this: &RawJsOnePasswordSsoUi,
        sso_login_url: &str,
        redirect_to: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = beginSsoEnrollment)]
    async fn begin_sso_enrollment(
        this: &RawJsOnePasswordSsoUi,
    ) -> Result<RawJsOnePasswordSsoEnrollment, JsValue>;

    /// The JavaScript object implementing a device enrollment in progress.
    #[wasm_bindgen(js_name = OnePasswordSsoEnrollment, typescript_type = "OnePasswordSsoEnrollment")]
    pub type RawJsOnePasswordSsoEnrollment;

    #[wasm_bindgen(catch, method, structural, js_name = cancelled)]
    async fn cancelled(this: &RawJsOnePasswordSsoEnrollment) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = updateStatus)]
    async fn update_status(
        this: &RawJsOnePasswordSsoEnrollment,
        status: OnePasswordSsoEnrollmentStatus,
        message: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = provideVerificationCode)]
    async fn provide_verification_code(
        this: &RawJsOnePasswordSsoEnrollment,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = endEnrollment)]
    async fn end_enrollment(
        this: &RawJsOnePasswordSsoEnrollment,
        result: OnePasswordSsoEnrollmentResult,
    ) -> Result<JsValue, JsValue>;

    /// The JavaScript object implementing the secure storage.
    #[wasm_bindgen(js_name = OnePasswordSecureStorage, typescript_type = "OnePasswordSecureStorage")]
    pub type RawJsOnePasswordSecureStorage;

    #[wasm_bindgen(catch, method, structural, js_name = loadString)]
    async fn load_string(
        this: &RawJsOnePasswordSecureStorage,
        name: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = storeString)]
    async fn store_string(
        this: &RawJsOnePasswordSecureStorage,
        name: &str,
        value: &str,
    ) -> Result<JsValue, JsValue>;
}

/// Adapts the JavaScript single sign-on prompts to [`OnePasswordSsoUi`], pinned to their thread
/// like [`JsOnePasswordTwoFactorUi`].
pub(crate) struct JsOnePasswordSsoUi(ThreadBoundRunner<RawJsOnePasswordSsoUi>);

impl JsOnePasswordSsoUi {
    pub(crate) fn new(ui: RawJsOnePasswordSsoUi) -> Self {
        Self(ThreadBoundRunner::new(ui))
    }
}

#[async_trait]
impl OnePasswordSsoUi for JsOnePasswordSsoUi {
    async fn perform_sso_login(
        &self,
        sso_login_url: &str,
        redirect_to: &str,
    ) -> OnePasswordSsoLoginResult {
        let sso_login_url = sso_login_url.to_owned();
        let redirect_to = redirect_to.to_owned();
        let redirected_to = self
            .0
            .run_in_thread(move |ui| async move {
                ui.perform_sso_login(&sso_login_url, &redirect_to)
                    .await
                    .ok()
                    .and_then(|url| url.as_string())
            })
            .await;

        match redirected_to {
            Ok(Some(url)) => OnePasswordSsoLoginResult::RedirectedTo(url),
            Ok(None) | Err(_) => OnePasswordSsoLoginResult::Cancel,
        }
    }

    async fn begin_sso_enrollment(&self) -> Box<dyn OnePasswordSsoEnrollment> {
        // The enrollment object is `!Send` too, so its runner is created on the JS thread and only
        // the runner comes back.
        let enrollment = self
            .0
            .run_in_thread(|ui| async move {
                let enrollment = ui.begin_sso_enrollment().await.ok()?;
                Some(ThreadBoundRunner::new(enrollment))
            })
            .await;

        match enrollment {
            Ok(Some(runner)) => Box::new(JsOnePasswordSsoEnrollment(runner)),
            Ok(None) | Err(_) => Box::new(CancelledEnrollment),
        }
    }
}

/// Adapts the JavaScript enrollment object to [`OnePasswordSsoEnrollment`].
struct JsOnePasswordSsoEnrollment(ThreadBoundRunner<RawJsOnePasswordSsoEnrollment>);

#[async_trait]
impl OnePasswordSsoEnrollment for JsOnePasswordSsoEnrollment {
    async fn cancelled(&self) {
        // Failing closed: a rejection or a dead runner cancels the enrollment like the user would.
        let _ = self
            .0
            .run_in_thread(|enrollment| async move {
                let _ = enrollment.cancelled().await;
            })
            .await;
    }

    async fn update_status(&self, status: OnePasswordSsoEnrollmentStatus, message: &str) {
        let message = message.to_owned();
        let _ = self
            .0
            .run_in_thread(move |enrollment| async move {
                let _ = enrollment.update_status(status, &message).await;
            })
            .await;
    }

    async fn provide_verification_code(&self) -> OnePasswordVerificationCodeResult {
        let code = self
            .0
            .run_in_thread(|enrollment| async move {
                enrollment
                    .provide_verification_code()
                    .await
                    .ok()
                    .and_then(|code| code.as_string())
            })
            .await;

        match code {
            Ok(Some(code)) => OnePasswordVerificationCodeResult::Code(code),
            Ok(None) | Err(_) => OnePasswordVerificationCodeResult::Cancel,
        }
    }

    async fn end_enrollment(&self, result: OnePasswordSsoEnrollmentResult) {
        let _ = self
            .0
            .run_in_thread(move |enrollment| async move {
                let _ = enrollment.end_enrollment(result).await;
            })
            .await;
    }
}

/// The enrollment of a UI that could not show one, which cancels it right away.
struct CancelledEnrollment;

#[async_trait]
impl OnePasswordSsoEnrollment for CancelledEnrollment {
    async fn cancelled(&self) {}

    async fn update_status(&self, _status: OnePasswordSsoEnrollmentStatus, _message: &str) {}

    async fn provide_verification_code(&self) -> OnePasswordVerificationCodeResult {
        OnePasswordVerificationCodeResult::Cancel
    }

    async fn end_enrollment(&self, _result: OnePasswordSsoEnrollmentResult) {}
}

/// Adapts the JavaScript secure storage to [`OnePasswordSecureStorage`], pinned to its thread like
/// [`JsOnePasswordTwoFactorUi`].
pub(crate) struct JsOnePasswordSecureStorage(ThreadBoundRunner<RawJsOnePasswordSecureStorage>);

impl JsOnePasswordSecureStorage {
    pub(crate) fn new(storage: RawJsOnePasswordSecureStorage) -> Self {
        Self(ThreadBoundRunner::new(storage))
    }
}

#[async_trait]
impl OnePasswordSecureStorage for JsOnePasswordSecureStorage {
    async fn load_string(&self, name: &str) -> Result<Option<String>, String> {
        let name = name.to_owned();
        self.0
            .run_in_thread(move |storage| async move {
                storage
                    .load_string(&name)
                    .await
                    .map_err(rejection_message)
                    .and_then(stored_string)
            })
            .await
            .map_err(|error| error.to_string())?
    }

    async fn store_string(&self, name: &str, value: String) -> Result<(), String> {
        let name = name.to_owned();
        self.0
            .run_in_thread(move |storage| async move {
                storage
                    .store_string(&name, &value)
                    .await
                    .map(|_| ())
                    .map_err(rejection_message)
            })
            .await
            .map_err(|error| error.to_string())?
    }
}

/// A stored string, or `None` for `undefined` and `null`. Anything else is an error rather than a
/// missing value, which would make the device enroll again and overwrite what is there.
fn stored_string(value: JsValue) -> Result<Option<String>, String> {
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    value
        .as_string()
        .map(Some)
        .ok_or_else(|| "the storage returned a value that is not a string".to_string())
}

/// What a rejected storage call says. A string rejection is passed on as is. Anything else, such as
/// an `Error`, gets a generic message as its text cannot be read without js-sys.
fn rejection_message(rejection: JsValue) -> String {
    rejection
        .as_string()
        .unwrap_or_else(|| "the storage rejected the call".to_string())
}
