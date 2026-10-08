//! What lets this device sign in again without an enrollment: the device key, the obfuscated
//! format its derivation parameters are kept in locally, and the credential bundle encrypted under
//! that key, which the server keeps.

use data_encoding::BASE64URL_NOPAD;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha384;
use zeroize::Zeroizing;

use super::super::{
    SecureStorage,
    device::generate_device_uuid,
    error::OnePasswordError,
    opdata::{AesKey, Encrypted, decode64_loose},
    wire::{self, CredentialBundle, EncryptedEnvelope, LocalUserInfo},
};

/// The HKDF `info` that domain separates the device key from the other 1Password derivations.
const DEVICE_KEY_INFO: &[u8] = b"1P_SSO_CREDENTIAL_BUNDLE_KEY:LOCAL";

/// Binds the credential bundle encrypted under the device key to this one use.
const CREDENTIAL_BUNDLE_AAD: &[u8] = b"1P_SSO_CREDENTIAL_BUNDLE:LOCAL2";

/// The key the derivation parameters are obfuscated with before they land in local storage.
///
/// It is hardcoded, exactly like in the 1Password web app, so this hides the parameters from a
/// casual look at the storage and nothing more. It is up to the caller to keep the storage secure.
const OBFUSCATION_KEY_ID: &str = "3tnqywhecddkhvl375l6yu7qri";
const OBFUSCATION_KEY: &[u8; 32] = b"01be638ec19d0b5bf7a310239d817aa1";

/// The secure storage name of the local credentials of one user, so a storage can serve several
/// accounts.
pub(super) fn credentials_name(user_uuid: &str) -> String {
    format!("sso-credentials-{user_uuid}")
}

const IV_SIZE: usize = 12;
const DEVICE_KEY_SIZE: usize = 32;
const SEED_SIZE: usize = 32;
const SALT_SIZE: usize = 48;

/// The parameters a device key is derived from.
///
/// Deliberately not `Debug`: the seed is key material. It only ever reaches storage through the
/// obfuscated envelope of [`encrypt_for_storage`].
pub(super) struct DeviceKeyDerivation {
    /// A fresh device-style uuid that doubles as the key id.
    pub id: String,
    /// The random bytes the device key is derived from.
    pub seed: Zeroizing<Vec<u8>>,
    /// The random bytes stored next to the seed. The 1Password clients generate and keep a salt
    /// but never feed it to the derivation, so neither does this port.
    pub salt: Zeroizing<Vec<u8>>,
}

/// Generates fresh derivation parameters: a new key id, a random seed and a random salt.
pub(super) fn generate_device_key_derivation() -> DeviceKeyDerivation {
    DeviceKeyDerivation {
        id: generate_device_uuid(),
        seed: random_bytes(SEED_SIZE),
        salt: random_bytes(SALT_SIZE),
    }
}

/// Derives the device key from the seed, salted with the key id.
pub(super) fn derive_device_key(derivation: &DeviceKeyDerivation) -> AesKey {
    let hkdf = Hkdf::<Sha384>::new(Some(derivation.id.as_bytes()), &derivation.seed);
    let mut key = Zeroizing::new([0u8; DEVICE_KEY_SIZE]);
    hkdf.expand(DEVICE_KEY_INFO, key.as_mut())
        .expect("32 bytes is well under HKDF's length limit");
    AesKey::new(derivation.id.clone(), key.to_vec())
}

/// Decrypts the stored derivation and derives the device key from it.
pub(super) fn load_and_derive_device_key(
    envelope: &EncryptedEnvelope,
) -> Result<AesKey, OnePasswordError> {
    Ok(derive_device_key(&decrypt_from_storage(envelope)?))
}

/// Encrypts the derivation parameters for storage, with the caller supplied IV.
fn encrypt_for_storage_with_iv(
    derivation: &DeviceKeyDerivation,
    iv: &[u8],
) -> Result<EncryptedEnvelope, OnePasswordError> {
    let json = serde_json::to_vec(&wire::DeviceKeyDerivation {
        kid: derivation.id.clone(),
        k: Zeroizing::new(BASE64URL_NOPAD.encode(derivation.seed.as_slice())),
        s: Zeroizing::new(BASE64URL_NOPAD.encode(derivation.salt.as_slice())),
    })
    .map(Zeroizing::new)
    .map_err(|_| OnePasswordError::Internal("failed to serialize the device key".into()))?;
    obfuscation_key(OBFUSCATION_KEY_ID).encrypt(&json, iv)
}

/// Encrypts the derivation parameters for storage under a fresh IV, as production writes it.
pub(super) fn encrypt_for_storage(
    derivation: &DeviceKeyDerivation,
) -> Result<EncryptedEnvelope, OnePasswordError> {
    encrypt_for_storage_with_iv(derivation, &random_iv())
}

/// Decrypts the stored derivation parameters. The obfuscation key id comes from the envelope
/// itself, so the format stays readable if the id ever changes.
fn decrypt_from_storage(
    envelope: &EncryptedEnvelope,
) -> Result<DeviceKeyDerivation, OnePasswordError> {
    let encrypted = Encrypted::parse(envelope)?;
    let json = Zeroizing::new(obfuscation_key(&encrypted.key_id).decrypt(&encrypted)?);
    let model: wire::DeviceKeyDerivation =
        serde_json::from_slice(&json).map_err(|_| OnePasswordError::Parse)?;

    Ok(DeviceKeyDerivation {
        id: model.kid,
        seed: Zeroizing::new(decode64_loose(&model.k)?),
        salt: Zeroizing::new(decode64_loose(&model.s)?),
    })
}

/// Encrypts the credential bundle under the device key for the server to keep, with the caller
/// supplied IV.
fn encrypt_credential_bundle_with_iv(
    bundle: &CredentialBundle,
    device_key: &AesKey,
    iv: &[u8],
) -> Result<EncryptedEnvelope, OnePasswordError> {
    let json = serde_json::to_vec(bundle)
        .map(Zeroizing::new)
        .map_err(|_| {
            OnePasswordError::Internal("failed to serialize the credential bundle".into())
        })?;
    device_key.encrypt_with_aad(&json, iv, CREDENTIAL_BUNDLE_AAD)
}

/// Encrypts the credential bundle under the device key for the server to keep under a fresh IV, as
/// production writes it.
pub(super) fn encrypt_credential_bundle(
    bundle: &CredentialBundle,
    device_key: &AesKey,
) -> Result<EncryptedEnvelope, OnePasswordError> {
    encrypt_credential_bundle_with_iv(bundle, device_key, &random_iv())
}

/// Decrypts the credential bundle the server keeps for this device with the device key.
pub(super) fn decrypt_credential_bundle(
    envelope: &EncryptedEnvelope,
    device_key: &AesKey,
) -> Result<CredentialBundle, OnePasswordError> {
    let encrypted = Encrypted::parse(envelope)?;
    let json = Zeroizing::new(device_key.decrypt_with_aad(&encrypted, CREDENTIAL_BUNDLE_AAD)?);

    // The error is dropped, serde echoes the offending value.
    serde_json::from_slice(&json).map_err(|_| OnePasswordError::Parse)
}

/// Reads the local credentials record of `user_uuid`. A missing value, a record that does not
/// parse and one that belongs to another user all mean there is nothing to restore, like the C#
/// `Try` wrapper there. A storage that fails to read is an error: the record may well be there.
pub(super) async fn load_local_credentials(
    storage: &dyn SecureStorage,
    user_uuid: &str,
) -> Result<Option<LocalUserInfo>, OnePasswordError> {
    let json = storage
        .load_string(&credentials_name(user_uuid))
        .await
        .map_err(OnePasswordError::SecureStorage)?;

    // Wiped because the fixed obfuscation key opens the derivation inside.
    let Some(json) = json.map(Zeroizing::new) else {
        return Ok(None);
    };
    let record: Option<LocalUserInfo> = serde_json::from_str(&json).ok();
    Ok(record.filter(|record| record.user_id.as_deref() == Some(user_uuid)))
}

/// Writes the local credentials record of `user_uuid`, replacing whatever is there.
pub(super) async fn store_local_credentials(
    storage: &dyn SecureStorage,
    user_uuid: &str,
    info: &LocalUserInfo,
) -> Result<(), OnePasswordError> {
    let json = serde_json::to_string(info).map_err(|_| {
        OnePasswordError::Internal("failed to serialize the local credentials".into())
    })?;
    storage
        .store_string(&credentials_name(user_uuid), json)
        .await
        .map_err(OnePasswordError::SecureStorage)
}

fn obfuscation_key(id: &str) -> AesKey {
    AesKey::new(id, OBFUSCATION_KEY.to_vec())
}

fn random_iv() -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    bitwarden_random::rng().fill_bytes(&mut iv);
    iv
}

fn random_bytes(count: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0u8; count]);
    bitwarden_random::rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;

    use super::{
        super::test_support::{RecordingStorage, hex, vectors},
        *,
    };

    fn vector_derivation() -> DeviceKeyDerivation {
        let vectors = vectors().local;
        DeviceKeyDerivation {
            id: vectors.device_key_id,
            seed: Zeroizing::new(hex(&vectors.device_key_seed)),
            salt: Zeroizing::new(hex(&vectors.device_key_salt)),
        }
    }

    fn vector_iv(envelope: &EncryptedEnvelope) -> Vec<u8> {
        decode64_loose(envelope.iv.as_deref().expect("the vector carries an iv"))
            .expect("valid base64")
    }

    fn vector_bundle() -> CredentialBundle {
        serde_json::from_str(&vectors().local.serialized_credential_bundle).expect("valid bundle")
    }

    /// The envelope fields are compared as a tuple: the whole point is matching every byte.
    fn envelope_fields(
        envelope: &EncryptedEnvelope,
    ) -> (String, String, String, Option<String>, String) {
        (
            envelope.kid.clone(),
            envelope.enc.clone(),
            envelope.cty.clone(),
            envelope.iv.clone(),
            envelope.data.clone(),
        )
    }

    #[test]
    fn generates_fresh_derivation_parameters() {
        let one = generate_device_key_derivation();
        let two = generate_device_key_derivation();

        assert_eq!(one.id.len(), 26);
        assert_eq!(one.seed.len(), SEED_SIZE);
        assert_eq!(one.salt.len(), SALT_SIZE);
        assert_ne!(one.id, two.id);
        assert_ne!(one.seed.as_slice(), two.seed.as_slice());
        assert_ne!(one.salt.as_slice(), two.salt.as_slice());
    }

    #[test]
    fn derives_the_device_key() {
        let vectors = vectors().local;

        let key = derive_device_key(&vector_derivation());

        assert_eq!(key.id, vectors.device_key_id);
        assert_eq!(HEXLOWER.encode(&key.key), vectors.device_key);
    }

    #[test]
    fn decrypts_the_stored_derivation() {
        let vectors = vectors().local;

        let derivation =
            decrypt_from_storage(&vectors.stored_device_key_derivation).expect("decrypts");

        assert_eq!(derivation.id, vectors.device_key_id);
        assert_eq!(derivation.seed.as_slice(), hex(&vectors.device_key_seed));
        assert_eq!(derivation.salt.as_slice(), hex(&vectors.device_key_salt));
    }

    #[test]
    fn encrypts_the_derivation_byte_for_byte() {
        let vectors = vectors().local;
        let stored = vectors.stored_device_key_derivation;

        let envelope = encrypt_for_storage_with_iv(&vector_derivation(), &vector_iv(&stored))
            .expect("encrypts");

        assert_eq!(envelope_fields(&envelope), envelope_fields(&stored));
    }

    #[test]
    fn tampering_with_the_stored_derivation_fails() {
        let mut envelope = vectors().local.stored_device_key_derivation;
        envelope.data.replace_range(0..1, "C");

        assert!(decrypt_from_storage(&envelope).is_err());
    }

    #[test]
    fn round_trips_the_derivation_through_a_fresh_iv() {
        let derivation = generate_device_key_derivation();

        let envelope = encrypt_for_storage(&derivation).expect("encrypts");
        let restored = decrypt_from_storage(&envelope).expect("decrypts");

        assert_eq!(restored.id, derivation.id);
        assert_eq!(restored.seed.as_slice(), derivation.seed.as_slice());
        assert_eq!(restored.salt.as_slice(), derivation.salt.as_slice());
    }

    #[test]
    fn serializes_the_credential_bundle_exactly() {
        assert_eq!(
            serde_json::to_vec(&vector_bundle()).expect("serializes"),
            vectors().local.serialized_credential_bundle.as_bytes()
        );
    }

    #[test]
    fn encrypts_the_credential_bundle_byte_for_byte() {
        let vectors = vectors().local;
        let stored = vectors.encrypted_credential_bundle;
        let device_key = derive_device_key(&vector_derivation());

        let envelope =
            encrypt_credential_bundle_with_iv(&vector_bundle(), &device_key, &vector_iv(&stored))
                .expect("encrypts");

        assert_eq!(envelope_fields(&envelope), envelope_fields(&stored));
    }

    #[test]
    fn decrypts_the_credential_bundle() {
        let vectors = vectors().local;
        let device_key = derive_device_key(&vector_derivation());

        let bundle = decrypt_credential_bundle(&vectors.encrypted_credential_bundle, &device_key)
            .expect("decrypts");

        assert_eq!(
            serde_json::to_vec(&bundle).expect("serializes"),
            vectors.serialized_credential_bundle.as_bytes()
        );
        assert_eq!(bundle.auk.kid, "mp");
    }

    #[test]
    fn decrypting_the_bundle_with_another_device_key_fails() {
        let vectors = vectors().local;
        let other = derive_device_key(&generate_device_key_derivation());

        assert!(decrypt_credential_bundle(&vectors.encrypted_credential_bundle, &other).is_err());
    }

    #[test]
    fn round_trips_the_bundle_through_a_fresh_iv() {
        let device_key = derive_device_key(&generate_device_key_derivation());

        let envelope = encrypt_credential_bundle(&vector_bundle(), &device_key).expect("encrypts");
        let bundle = decrypt_credential_bundle(&envelope, &device_key).expect("decrypts");

        assert_eq!(bundle.srpx, vector_bundle().srpx);
    }

    #[tokio::test]
    async fn loads_the_c_written_record_and_restores_the_bundle() {
        let storage = RecordingStorage::default();
        storage
            .store_string(
                &credentials_name("USERUUID"),
                vectors().local.local_user_info_json,
            )
            .await
            .expect("stores");

        let info = load_local_credentials(&storage, "USERUUID")
            .await
            .expect("reads")
            .expect("finds the record");
        let vectors = vectors().local;
        assert_eq!(info.user_id.as_deref(), Some("USERUUID"));
        assert_eq!(info.account_id.as_deref(), Some("ACCOUNTUUID"));
        assert_eq!(
            info.credentials_encryption_key_id.as_deref(),
            Some(vectors.device_key_id.as_str())
        );

        let device_key = load_and_derive_device_key(
            info.device_key_derivation
                .as_ref()
                .expect("the record carries the derivation"),
        )
        .expect("derives");
        let bundle = decrypt_credential_bundle(&vectors.encrypted_credential_bundle, &device_key)
            .expect("decrypts");

        assert_eq!(bundle.srpx, vector_bundle().srpx);
        assert_eq!(bundle.auk.k, vector_bundle().auk.k);
    }

    #[tokio::test]
    async fn missing_or_broken_storage_loads_as_none() {
        let storage = RecordingStorage::default();
        let name = credentials_name("USERUUID");
        assert!(
            load_local_credentials(&storage, "USERUUID")
                .await
                .expect("reads")
                .is_none()
        );

        storage
            .store_string(&name, "not json".into())
            .await
            .expect("stores");
        assert!(
            load_local_credentials(&storage, "USERUUID")
                .await
                .expect("reads")
                .is_none()
        );

        storage
            .store_string(&name, "{\"userId\":123}".into())
            .await
            .expect("stores");
        assert!(
            load_local_credentials(&storage, "USERUUID")
                .await
                .expect("reads")
                .is_none()
        );
    }

    #[tokio::test]
    async fn stores_and_reloads_the_record() {
        let storage = RecordingStorage::default();
        let original: LocalUserInfo =
            serde_json::from_str(&vectors().local.local_user_info_json).expect("parses");

        store_local_credentials(&storage, "USERUUID", &original)
            .await
            .expect("stores");

        let reloaded = load_local_credentials(&storage, "USERUUID")
            .await
            .expect("reads")
            .expect("finds the record");
        assert_eq!(
            serde_json::to_value(&reloaded).expect("serializes"),
            serde_json::to_value(&original).expect("serializes")
        );
    }

    #[tokio::test]
    async fn users_sharing_a_storage_keep_their_own_records() {
        let storage = RecordingStorage::default();
        let record = |user_id: &str, account_id: &str| LocalUserInfo {
            user_id: Some(user_id.into()),
            account_id: Some(account_id.into()),
            ..LocalUserInfo::default()
        };

        store_local_credentials(&storage, "ALICE", &record("ALICE", "ALICE_ACCOUNT"))
            .await
            .expect("stores");
        store_local_credentials(&storage, "BOB", &record("BOB", "BOB_ACCOUNT"))
            .await
            .expect("stores");

        for (user, account) in [("ALICE", "ALICE_ACCOUNT"), ("BOB", "BOB_ACCOUNT")] {
            let loaded = load_local_credentials(&storage, user)
                .await
                .expect("reads")
                .expect("finds the record");
            assert_eq!(loaded.account_id.as_deref(), Some(account));
        }
        assert!(
            load_local_credentials(&storage, "CAROL")
                .await
                .expect("reads")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_record_of_another_user_is_ignored_and_left_in_place() {
        let storage = RecordingStorage::default();
        let json = vectors().local.local_user_info_json;
        storage
            .store_string(&credentials_name("SOMEONE_ELSE"), json.clone())
            .await
            .expect("stores");

        assert!(
            load_local_credentials(&storage, "SOMEONE_ELSE")
                .await
                .expect("reads")
                .is_none()
        );
        assert_eq!(
            storage
                .load_string(&credentials_name("SOMEONE_ELSE"))
                .await
                .expect("reads"),
            Some(json)
        );
    }
}
