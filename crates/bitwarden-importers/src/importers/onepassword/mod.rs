//! 1Password importer.
//!
//! [`access`] is the Bitwarden-agnostic client that logs in and downloads the vaults;
//! [`convert`] maps what it returns onto the importer's parsed shape.

// `pub` for the `test-utils` re-export the out-of-tree CLI drives.
// TODO: Make both `pub(crate)` once that CLI is retired.
pub mod access;
pub mod convert;
#[cfg(feature = "wasm")]
pub(crate) mod wasm;

use access::OnePasswordError;

use crate::ImportError;

impl From<OnePasswordError> for ImportError {
    fn from(error: OnePasswordError) -> Self {
        match error {
            OnePasswordError::BadCredentials => ImportError::OnePasswordBadCredentials,
            OnePasswordError::TwoFactorRequired => ImportError::OnePasswordTwoFactorRequired,
            OnePasswordError::TwoFactorFailed => ImportError::OnePasswordTwoFactorFailed,
            OnePasswordError::Unsupported(what) => ImportError::OnePasswordUnsupported(what),
            OnePasswordError::Network(what) => ImportError::OnePasswordNetwork(what),
            // A payload that will not decrypt or parse is the same story to a user: the account
            // came back unreadable.
            OnePasswordError::Decryption | OnePasswordError::Parse => {
                ImportError::OnePasswordDecryption
            }
            // Neither of these can reach a caller as anything actionable, so they read as a
            // transport failure with the detail kept.
            OnePasswordError::NotFound => {
                ImportError::OnePasswordNetwork("the account or vault was not found".to_string())
            }
            OnePasswordError::Internal(what) => ImportError::OnePasswordNetwork(what),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every 1Password failure has to reach the UI as a code it can act on, so none of them may
    /// collapse into a generic error.
    #[test]
    fn every_failure_maps_to_a_code_the_ui_can_switch_on() {
        let mapped = |error: OnePasswordError| ImportError::from(error).to_string();

        assert_eq!(
            mapped(OnePasswordError::BadCredentials),
            "Incorrect 1Password email, password, or Secret Key"
        );
        assert_eq!(
            mapped(OnePasswordError::TwoFactorRequired),
            "The 1Password account requires a two-factor code"
        );
        assert_eq!(
            mapped(OnePasswordError::TwoFactorFailed),
            "The 1Password two-factor code was rejected"
        );
        assert_eq!(
            mapped(OnePasswordError::Unsupported("Duo".to_string())),
            "This 1Password account uses a sign-in method the importer does not support: Duo"
        );
        assert_eq!(
            mapped(OnePasswordError::Decryption),
            "The data 1Password returned could not be read"
        );
        assert_eq!(
            mapped(OnePasswordError::Parse),
            "The data 1Password returned could not be read"
        );
        assert_eq!(
            mapped(OnePasswordError::Network("timed out".to_string())),
            "Could not reach 1Password: timed out"
        );
    }
}
