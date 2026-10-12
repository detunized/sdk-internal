//! The credentials a password login needs.

use zeroize::Zeroize;

use super::{error::OnePasswordError, sign_in::SignInAddress};

/// The credentials for a password + Secret Key login.
///
/// Deliberately neither `Debug` nor `Serialize`: it holds the master password and Secret Key.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
#[derive(Clone)]
pub struct Credentials {
    /// The account's email address.
    pub username: String,
    /// The account's master password.
    pub password: String,
    /// The account's Secret Key (Account Key), such as `A3-XXXXXX-...`.
    pub account_key: String,
    /// Where the account signs in, such as `my.1password.com`.
    pub sign_in_address: SignInAddress,
}

impl Zeroize for Credentials {
    fn zeroize(&mut self) {
        self.password.zeroize();
        self.account_key.zeroize();
    }
}

// UniFFI records are lowered by moving out their fields, which Rust does not allow for a type that
// implements `Drop`. The access client owns the lowered record in a zeroizing guard instead.
#[cfg(not(feature = "uniffi"))]
impl Drop for Credentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The credentials for a single sign-on login.
///
/// Unlike [`Credentials`] there is no secret in here: the identity provider authenticates the
/// user and the enrolled device supplies the account keys.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Deserialize, tsify::Tsify),
    tsify(from_wasm_abi)
)]
#[derive(Debug, Clone)]
pub struct SsoCredentials {
    /// The account's email address.
    pub username: String,
    /// Where the account signs in, such as `my.1password.com`.
    pub sign_in_address: SignInAddress,
}

impl SsoCredentials {
    /// Rejects a blank username and normalizes the sign-in address.
    pub(super) fn validate(&mut self) -> Result<(), OnePasswordError> {
        if self.username.trim().is_empty() {
            return Err(OnePasswordError::Internal(
                "username (email) is required".into(),
            ));
        }
        self.sign_in_address.normalize()
    }
}
