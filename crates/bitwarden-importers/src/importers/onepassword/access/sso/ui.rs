//! Public callback contracts the SSO login flow drives.

use async_trait::async_trait;

/// Secure per-device storage the SSO flow keeps its local credentials in.
///
/// The implementation decides what "secure" means: an OS keychain, encrypted storage, or nothing
/// at all for a one-shot import that leaves no device credentials behind.
///
/// One storage can serve several accounts, as each keeps its record under a name of its own. The
/// names are opaque keys. An error fails the import and shows up in its message, so it must say
/// what went wrong without including a stored value.
#[async_trait]
pub trait SecureStorage: Send + Sync {
    /// Returns the value stored under `name`, or `None` when there is none.
    ///
    /// Fails when the storage cannot be read. Answering `None` instead would make the device
    /// enroll again and overwrite a value that is still there.
    async fn load_string(&self, name: &str) -> Result<Option<String>, String>;

    /// Stores the value under `name`, replacing any previous one.
    ///
    /// Fails when the value could not be stored.
    async fn store_string(&self, name: &str, value: String) -> Result<(), String>;
}

/// The outcome of the identity provider step of an SSO login.
pub enum SsoLoginResult {
    /// The full URL the identity provider redirected to. It carries the authorization code.
    RedirectedTo(String),
    /// The user gave up on the login.
    Cancel,
}

/// Callbacks that take the user through an SSO login.
#[async_trait]
pub trait SsoUi: Send + Sync {
    /// Opens `sso_login_url`, usually in a browser, and waits for the identity provider to
    /// redirect to `redirect_to`.
    async fn perform_sso_login(&self, sso_login_url: &str, redirect_to: &str) -> SsoLoginResult;

    /// Shows the device enrollment UI, which the login then drives through the returned context.
    /// Called when this device is not trusted yet, or its stored credentials no longer work.
    async fn begin_sso_enrollment(&self) -> Box<dyn SsoEnrollmentContext>;
}

/// The stage a device enrollment is in, for the UI to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, tsify::Tsify),
    tsify(into_wasm_abi, type_prefix = "OnePasswordSso")
)]
pub enum EnrollmentStatus {
    /// Waiting for the user to approve this device on one that is already enrolled.
    WaitingForApproval,
    /// Receiving the credentials from the approving device.
    ExchangingCredentials,
    /// Finishing the enrollment.
    Completing,
}

/// How a device enrollment ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, tsify::Tsify),
    tsify(into_wasm_abi, type_prefix = "OnePassword")
)]
pub enum SsoEnrollmentResult {
    /// The approving device handed over the credentials.
    Success,
    /// The user canceled.
    Canceled,
    /// The user denied the request on the approving device.
    Denied,
    /// Anything else went wrong.
    Failed,
}

/// The answer to the verification code prompt.
pub enum VerificationCodeResult {
    /// The code the approving device shows.
    Code(String),
    /// The user canceled.
    Cancel,
}

/// A device enrollment in progress: the UI shows its stage, asks for the verification code, and
/// lets the user cancel.
#[async_trait]
pub trait SsoEnrollmentContext: Send + Sync {
    /// Resolves when the user cancels the enrollment. An implementation that cannot cancel never
    /// resolves.
    async fn cancelled(&self);

    /// Shows the stage the enrollment has reached.
    async fn update_status(&self, status: EnrollmentStatus, message: &str);

    /// Asks for the verification code the approving device shows.
    async fn provide_verification_code(&self) -> VerificationCodeResult;

    /// Closes the enrollment UI. Called exactly once when the enrollment ends, unless the login is
    /// dropped halfway.
    async fn end_enrollment(&self, result: SsoEnrollmentResult);
}
