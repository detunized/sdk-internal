//! The CPace exchange that hands the credentials of an enrolled device to a new one, reverse
//! engineered from 1Password's WASM module: the local crypto, and the requests that carry it.
//!
//! The new device proves it knows the verification code the user reads off the enrolled device, and
//! both sides end up with the same key to move the credential bundle through the server.

use bitwarden_threading::time;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha384, Sha512};
use zeroize::Zeroizing;

use super::{
    super::{
        error::OnePasswordError,
        kdf,
        opdata::{AesKey, Encrypted, decode64_loose},
        rest::RestClient,
        wire::{self, CredentialBundle, EncryptedEnvelope, SuccessStatus},
    },
    UNTIL_RESULT_ATTEMPTS, UNTIL_RESULT_DELAY,
};

const PASSCODE_ITERATIONS: u32 = 100_000;

/// Pads the second hash input through the passcode hash to one 128 byte SHA-512 block.
const PADDING_LENGTH: usize = 76;

/// The key id of the exchange key, which also keys the first step of deriving it.
const TRANSPORT_KEY_ID: &str = "1P_SSO_ENROLLMENT_TRANSPORT_KEY";
const EXCHANGE_KEY_INFO: &[u8] = b"1P_SSO_CREDENTIAL_BUNDLE_KEY:ENROLL\x01";
const CREDENTIAL_BUNDLE_AAD: &[u8] = b"1P_SSO_CREDENTIAL_BUNDLE:ENROLL";

/// The first CPace message, from the enrolled device.
#[derive(Debug)]
struct MsgA {
    /// The enrolled device's public point.
    ya: RistrettoPoint,
    ad: Ad,
    /// The message as received, which goes into the transcript hash byte for byte.
    original_message: Vec<u8>,
}

/// The associated data of a CPace message.
#[derive(Debug)]
struct Ad {
    salt: Vec<u8>,
    session_id: Vec<u8>,
}

/// Parses the JSON of `msga`, after its base64 layer is removed.
///
/// Rejects a `ya` that is not the canonical encoding of a point, or is the identity, before
/// anything is sent back.
fn parse_msg_a(json: &[u8]) -> Result<MsgA, OnePasswordError> {
    let msg_a: wire::MsgA = serde_json::from_slice(json).map_err(|_| OnePasswordError::Parse)?;
    let ya = decompress_point(&decode64_loose(&msg_a.ya)?)?;
    if ya == RistrettoPoint::identity() {
        return Err(OnePasswordError::Internal(
            "the CPace point must not be the identity".into(),
        ));
    }

    Ok(MsgA {
        ya,
        ad: Ad {
            salt: decode64_loose(&msg_a.ad.salt)?,
            session_id: msg_a.ad.session_id,
        },
        original_message: json.to_vec(),
    })
}

/// Fails for anything but the canonical encoding of a point.
fn decompress_point(bytes: &[u8]) -> Result<RistrettoPoint, OnePasswordError> {
    CompressedRistretto::from_slice(bytes)
        .ok()
        .and_then(|point| point.decompress())
        .ok_or_else(|| OnePasswordError::Internal("invalid CPace point".into()))
}

/// Calculates `msgb`, the new device's answer to `msga`.
fn calculate_msg_b(
    username: &str,
    sign_in_address: &str,
    enrollment_uuid: &str,
    verification_code: &str,
    msg_a: &MsgA,
    client_secret: &[u8; 64],
) -> [u8; 32] {
    let passcode_hash = calculate_passcode_hash(verification_code, &msg_a.ad.salt);
    let first_hash = calculate_first_hash(username, sign_in_address, enrollment_uuid, msg_a);
    let second_hash = Zeroizing::new(calculate_second_hash(
        &first_hash,
        passcode_hash.as_slice(),
        msg_a,
    ));
    let generator = RistrettoPoint::from_uniform_bytes(&second_hash);
    multiply_by_client_scalar(&generator, client_secret)
}

/// Stretches the verification code, salted by the enrolled device.
fn calculate_passcode_hash(passcode: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(kdf::pbes2(passcode, salt, PASSCODE_ITERATIONS))
}

/// Binds the exchange to the user, the sign-in address and the enrollment.
fn calculate_first_hash(
    email: &str,
    sign_in_address: &str,
    enrollment_uuid: &str,
    msg_a: &MsgA,
) -> [u8; 64] {
    sha512(&leb128_prefixed(&[
        b"1P-SSO-TRUSTED-DEVICE",
        b"1P-SSO-NEW-DEVICE",
        email.as_bytes(),
        sign_in_address.as_bytes(),
        enrollment_uuid.as_bytes(),
        &msg_a.ad.salt,
        &[1],
    ]))
}

/// The input of the CPace generator, which binds the passcode to the first hash and the session.
fn calculate_second_hash(first_hash: &[u8], passcode_hash: &[u8], msg_a: &MsgA) -> [u8; 64] {
    sha512(&leb128_prefixed(&[
        b"CPaceRistretto255",
        passcode_hash,
        &[0; PADDING_LENGTH],
        first_hash,
        &msg_a.ad.session_id,
    ]))
}

/// Multiplies by the scalar the client secret reduces to, and compresses the result.
fn multiply_by_client_scalar(point: &RistrettoPoint, client_secret: &[u8; 64]) -> [u8; 32] {
    let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(client_secret));
    (point * *scalar).compress().to_bytes()
}

/// Prefixes every field with its length as LEB128, and concatenates them.
fn leb128_prefixed(fields: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut buffer = Zeroizing::new(Vec::new());
    for field in fields {
        write_leb128_prefixed(&mut buffer, field);
    }
    buffer
}

/// Writes `data` after its length, as the little endian base 128 varint the WASM module uses.
fn write_leb128_prefixed(buffer: &mut Vec<u8>, data: &[u8]) {
    let mut length = data.len();
    loop {
        let byte = (length & 0x7f) as u8;
        length >>= 7;
        if length == 0 {
            buffer.push(byte);
            break;
        }
        buffer.push(byte | 0x80);
    }
    buffer.extend_from_slice(data);
}

/// Would check `taga`, which proves the enrolled device knows the verification code too.
///
/// Not implemented: the server is trusted to relay an honest device.
fn verify_tag_a(_tag_a: &[u8]) {}

/// Calculates the shared secret `authB` and the `tagb` that proves knowing it.
fn calculate_auth_b_tag_b(
    client_secret: &[u8; 64],
    msg_a: &MsgA,
    msg_b: &[u8],
) -> (Zeroizing<[u8; 64]>, [u8; 64]) {
    let auth_a = calculate_auth_a_hash(msg_a, client_secret);
    let auth_b = calculate_auth_b_hash(auth_a.as_slice(), msg_a, msg_b);
    let tag_b = calculate_tag_b(auth_b.as_slice(), msg_b);
    (auth_b, tag_b)
}

/// The point both sides agree on: `ya` times the client scalar.
fn calculate_auth_a_hash(msg_a: &MsgA, client_secret: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(multiply_by_client_scalar(&msg_a.ya, client_secret))
}

/// The session secret, hashed over the whole transcript.
fn calculate_auth_b_hash(auth_a: &[u8], msg_a: &MsgA, msg_b: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut buffer = leb128_prefixed(&[b"CPaceRistretto255_ISK", &msg_a.ad.session_id, auth_a]);
    buffer.extend_from_slice(&msg_a.original_message);
    buffer.extend_from_slice(msg_b);
    Zeroizing::new(sha512(&buffer))
}

/// The MAC of `msgb` under a key derived from `authB`.
fn calculate_tag_b(auth_b: &[u8], msg_b: &[u8]) -> [u8; 64] {
    let mac_key = Zeroizing::new(<[u8; 64]>::from(
        Sha512::new()
            .chain_update(b"CPaceMac")
            .chain_update(auth_b)
            .finalize(),
    ));
    hmac_sha512(mac_key.as_slice(), msg_b)
}

/// Derives the key that encrypts the credential bundle in transit from `authB`.
fn derive_exchange_key(auth_b: &[u8]) -> Zeroizing<[u8; 32]> {
    let transport_key = hmac_sha384(TRANSPORT_KEY_ID.as_bytes(), auth_b);
    let exchange_key = hmac_sha384(transport_key.as_slice(), EXCHANGE_KEY_INFO);

    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&exchange_key[..32]);
    key
}

/// Decrypts the credential bundle the enrolled device shared.
fn decrypt_credentials(
    encrypted_credentials: &EncryptedEnvelope,
    exchange_key: &[u8],
) -> Result<CredentialBundle, OnePasswordError> {
    let key = AesKey::new(TRANSPORT_KEY_ID, exchange_key.to_vec());
    let encrypted = Encrypted::parse(encrypted_credentials)?;
    let credentials = Zeroizing::new(key.decrypt_with_aad(&encrypted, CREDENTIAL_BUNDLE_AAD)?);

    // The error is dropped, serde echoes the offending value.
    serde_json::from_slice(&credentials).map_err(|_| OnePasswordError::Parse)
}

fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

fn hmac_sha384(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 48]> {
    let mut mac =
        <Hmac<Sha384> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut mac =
        <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Runs the whole exchange over `rest` with a fresh random client secret and returns the
/// credentials the enrolled device shared.
pub(super) async fn perform_cpace(
    username: &str,
    sign_in_address: &str,
    sign_in_token: &str,
    enrollment_uuid: &str,
    verification_code: &str,
    rest: &RestClient,
) -> Result<CredentialBundle, OnePasswordError> {
    let mut client_secret = Zeroizing::new([0u8; 64]);
    bitwarden_random::rng().fill_bytes(&mut *client_secret);

    let msg_a = request_msg_a(sign_in_token, enrollment_uuid, rest).await?;

    let msg_b = calculate_msg_b(
        username,
        sign_in_address,
        enrollment_uuid,
        verification_code,
        &msg_a,
        &client_secret,
    );
    send_msg_b(&msg_b, sign_in_token, enrollment_uuid, rest).await?;

    let tag_a = get_tag_a(sign_in_token, enrollment_uuid, rest).await?;
    verify_tag_a(&tag_a);

    let (auth_b, tag_b) = calculate_auth_b_tag_b(&client_secret, &msg_a, &msg_b);
    send_tag_b(&tag_b, sign_in_token, enrollment_uuid, rest).await?;

    let encrypted_credentials =
        request_encrypted_credentials(sign_in_token, enrollment_uuid, rest).await?;
    let exchange_key = derive_exchange_key(auth_b.as_slice());

    decrypt_credentials(&encrypted_credentials, exchange_key.as_slice())
}

/// Fetches and parses the enrolled device's first message.
async fn request_msg_a(
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<MsgA, OnePasswordError> {
    let response: wire::CpaceMsgA = rest
        .post_json(
            &cpace_endpoint(enrollment_uuid, "msga"),
            sign_in_body(sign_in_token),
        )
        .await?;

    parse_msg_a(&decode64_loose(&response.msga)?)
}

/// Replies with `msgb` and expects the server to accept it.
async fn send_msg_b(
    msg_b: &[u8],
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let response: SuccessStatus = rest
        .put_json(
            &cpace_endpoint(enrollment_uuid, "msgb"),
            json!({
                "signInToken": sign_in_token,
                "msgb": BASE64URL_NOPAD.encode(msg_b),
            }),
        )
        .await?;

    expect_success(&response, "exchange credentials")
}

/// Waits for the enrolled device's `taga`, which only `verify_tag_a` looks at.
async fn get_tag_a(
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<Vec<u8>, OnePasswordError> {
    let result: wire::CpaceTagA = post_json_until_result(
        &cpace_endpoint(enrollment_uuid, "taga"),
        sign_in_body(sign_in_token),
        rest,
    )
    .await?;

    decode64_loose(&result.taga)
}

/// Replies with `tagb` and expects the server to accept it.
async fn send_tag_b(
    tag_b: &[u8],
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let response: SuccessStatus = rest
        .put_json(
            &cpace_endpoint(enrollment_uuid, "tagb"),
            json!({
                "signInToken": sign_in_token,
                "tagb": BASE64URL_NOPAD.encode(tag_b),
            }),
        )
        .await?;

    expect_success(&response, "submit tagb")
}

/// Waits for the credential bundle, still encrypted for the exchange key and so invisible to the
/// server that relays it.
async fn request_encrypted_credentials(
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<EncryptedEnvelope, OnePasswordError> {
    let result: wire::SharedCredentials = post_json_until_result(
        &enrollment_endpoint(enrollment_uuid, "share/credentials"),
        sign_in_body(sign_in_token),
        rest,
    )
    .await?;

    Ok(result.encrypted_credentials)
}

/// POSTs until the endpoint answers a body instead of the empty 200 it sends while the enrolled
/// device has not replied yet. The web frontend retries the same way.
async fn post_json_until_result<T: DeserializeOwned>(
    endpoint: &str,
    body: Value,
    rest: &RestClient,
) -> Result<T, OnePasswordError> {
    for _ in 0..UNTIL_RESULT_ATTEMPTS {
        match rest.post_json_or_empty(endpoint, body.clone()).await? {
            Some(result) => return Ok(result),
            None => time::sleep(UNTIL_RESULT_DELAY).await,
        }
    }

    Err(OnePasswordError::Internal(format!(
        "failed to get a response from the server (endpoint: {endpoint})"
    )))
}

/// The body every CPace request carries besides the messages themselves.
fn sign_in_body(sign_in_token: &str) -> Value {
    json!({ "signInToken": sign_in_token })
}

/// The server confirms each CPace message with `success: 1`.
fn expect_success(response: &SuccessStatus, action: &str) -> Result<(), OnePasswordError> {
    if response.success != 1 {
        return Err(OnePasswordError::Internal(format!("failed to {action}")));
    }
    Ok(())
}

/// `v3/device/enrollments/{enrollmentUuid}/{method}`
fn enrollment_endpoint(enrollment_uuid: &str, method: &str) -> String {
    format!("v3/device/enrollments/{enrollment_uuid}/{method}")
}

/// The CPace endpoints, under the enrollment's `cpace` prefix.
fn cpace_endpoint(enrollment_uuid: &str, method: &str) -> String {
    enrollment_endpoint(enrollment_uuid, &format!("cpace/{method}"))
}
