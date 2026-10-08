//! The whole SSO login against a fake server: what it asks of the identity provider, of the
//! storage and of the server, and what it leaves behind.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitwarden_api_base::new_http_client;
use serde_json::json;
use wiremock::{Mock, ResponseTemplate, matchers};
use zeroize::Zeroizing;

use super::{
    super::{
        client::{Client, MasterKey, download_vaults},
        credentials::SsoCredentials,
        error::OnePasswordError,
        model::DownloadedAccount,
        session::Session,
        sign_in::{SignInAddress, SignInDomain},
        wire::{EncryptedEnvelope, LocalUserInfo},
    },
    fake_server::{
        ACCOUNT_UUID, DEVICE_UUID, FakeServer, REDIRECTED_TO, SSO_LOGIN_URL, SSO_SESSION_UUID,
        USER_UUID, USERNAME, account_unlock_key, client_info, verify_response,
    },
    local::{
        decrypt_credential_bundle, encrypt_for_storage, generate_device_key_derivation,
        load_and_derive_device_key, load_local_credentials,
    },
    sso_login,
    test_support::{
        RecordingStorage, SIGN_IN_TOKEN, mock_enrolled_device_for_any_client, quick_timing, vectors,
    },
    ui::{
        EnrollmentStatus, SsoEnrollmentContext, SsoEnrollmentResult, SsoLoginResult, SsoUi,
        VerificationCodeResult,
    },
};

/// The device key id of the stored credentials in the vectors.
const STORED_KEY_ID: &str = "m3h6kz4qjbj5xlzp7g2vy3tq4e";

/// The user of the login: signs in with the identity provider or gives up on it, and enters the
/// verification code of the vectors when the device is enrolled.
struct ScriptedUser {
    login: Mutex<Option<SsoLoginResult>>,
    enrollments: Arc<Mutex<Vec<SsoEnrollmentResult>>>,
}

impl ScriptedUser {
    fn signing_in() -> ScriptedUser {
        ScriptedUser::new(SsoLoginResult::RedirectedTo(REDIRECTED_TO.into()))
    }

    fn giving_up() -> ScriptedUser {
        ScriptedUser::new(SsoLoginResult::Cancel)
    }

    fn new(login: SsoLoginResult) -> ScriptedUser {
        ScriptedUser {
            login: Mutex::new(Some(login)),
            enrollments: Arc::default(),
        }
    }

    /// How the enrollments that ran ended.
    fn enrollments(&self) -> Vec<SsoEnrollmentResult> {
        self.enrollments.lock().expect("not poisoned").clone()
    }
}

#[async_trait]
impl SsoUi for ScriptedUser {
    async fn perform_sso_login(&self, sso_login_url: &str, redirect_to: &str) -> SsoLoginResult {
        assert_eq!(sso_login_url, SSO_LOGIN_URL);
        assert_eq!(redirect_to, "https://acme.1password.com/sso/oidc/redirect/");
        self.login
            .lock()
            .expect("not poisoned")
            .take()
            .expect("the identity provider is asked once")
    }

    async fn begin_sso_enrollment(&self) -> Box<dyn SsoEnrollmentContext> {
        Box::new(EnrollingUser {
            ended: self.enrollments.clone(),
        })
    }
}

struct EnrollingUser {
    ended: Arc<Mutex<Vec<SsoEnrollmentResult>>>,
}

#[async_trait]
impl SsoEnrollmentContext for EnrollingUser {
    async fn cancelled(&self) {
        std::future::pending().await
    }

    async fn update_status(&self, _: EnrollmentStatus, _: &str) {}

    async fn provide_verification_code(&self) -> VerificationCodeResult {
        VerificationCodeResult::Code(vectors().cpace.verification_code)
    }

    async fn end_enrollment(&self, result: SsoEnrollmentResult) {
        self.ended.lock().expect("not poisoned").push(result);
    }
}

fn credentials() -> SsoCredentials {
    SsoCredentials {
        username: USERNAME.into(),
        device_uuid: DEVICE_UUID.into(),
        sign_in_address: SignInAddress {
            subdomain: "acme".into(),
            domain: SignInDomain::Global,
        },
    }
}

async fn sign_in(
    server: &FakeServer,
    ui: &ScriptedUser,
    storage: &RecordingStorage,
) -> Result<(Session, Zeroizing<Vec<u8>>), OnePasswordError> {
    sso_login(
        &credentials(),
        &client_info(),
        ui,
        storage,
        &server.rest(),
        &quick_timing(),
    )
    .await
}

/// The record of the vectors, for another user or another device key.
fn stored_record(user_id: &str, key_id: &str) -> String {
    let record = LocalUserInfo {
        user_id: Some(user_id.into()),
        account_id: Some(ACCOUNT_UUID.into()),
        credentials_encryption_key_id: Some(key_id.into()),
        device_key_derivation: Some(
            encrypt_for_storage(&generate_device_key_derivation()).expect("encrypts"),
        ),
    };
    serde_json::to_string(&record).expect("serializes")
}

/// What the server needs to enroll a device: the enrollment, the approval of an enrolled device
/// and the credential exchange with it.
async fn mock_enrollment(server: &FakeServer) {
    let cpace = vectors().cpace;
    server
        .mock
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path("/api/v3/device/enrollments"))
                .and(matchers::header("x-agilebits-session-id", SSO_SESSION_UUID))
                .and(matchers::body_json(json!({"signInToken": SIGN_IN_TOKEN})))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "enrollmentUuid": cpace.enrollment_uuid,
                })))
                .expect(1),
        )
        .await;
    server
        .mock
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path("/api/v3/device/enrollments/status"))
                .and(matchers::header("x-agilebits-session-id", SSO_SESSION_UUID))
                .and(matchers::body_json(json!({
                    "signInToken": SIGN_IN_TOKEN,
                    "enrollmentUuid": cpace.enrollment_uuid,
                })))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"status": "WAITING_FOR_CODE"})),
                ),
        )
        .await;
    mock_enrolled_device_for_any_client(&server.mock, &cpace, &server.sign_in_address()).await;
}

/// Downloads the account with the account unlock key and checks it has what the server holds.
async fn assert_downloads_the_account(
    session: Session,
    master_key: Zeroizing<Vec<u8>>,
) -> DownloadedAccount {
    assert_eq!(*master_key, account_unlock_key());

    let account = download_vaults(MasterKey::Known(master_key), &session)
        .await
        .expect("the keysets open with the account unlock key");

    assert!(account.skipped_vaults.is_empty());
    let [vault] = account.vaults.as_slice() else {
        panic!("expected one vault, got {}", account.vaults.len());
    };
    assert_eq!(vault.name, "Personal");
    assert!(vault.skipped_items.is_empty());
    let [item] = vault.items.as_slice() else {
        panic!("expected one item, got {}", vault.items.len());
    };
    assert_eq!(item.overview.title.as_deref(), Some("Example"));
    account
}

/// The device credentials request of a new device, and what it left in storage: the device key
/// that opens the credentials the server was given.
async fn assert_committed(server: &FakeServer, storage: &RecordingStorage) -> LocalUserInfo {
    let [request] = server
        .device_credentials()
        .try_into()
        .unwrap_or_else(|requests: Vec<_>| panic!("expected one request, got {}", requests.len()));
    let stored = load_local_credentials(storage, USER_UUID)
        .await
        .expect("the storage reads")
        .expect("the device key is stored");

    let key_id = stored
        .credentials_encryption_key_id
        .as_deref()
        .expect("the key id is stored");
    assert_eq!(request["keyId"], key_id);
    assert_eq!(request["enrollmentUuid"], vectors().cpace.enrollment_uuid);
    assert_eq!(request["deviceCredentials"]["v"], 2);
    assert_eq!(stored.user_id.as_deref(), Some(USER_UUID));
    assert_eq!(stored.account_id.as_deref(), Some(ACCOUNT_UUID));

    let device_key = load_and_derive_device_key(
        stored
            .device_key_derivation
            .as_ref()
            .expect("the derivation is stored"),
    )
    .expect("the derivation opens");
    assert_eq!(device_key.id, key_id);
    let encrypted: EncryptedEnvelope =
        serde_json::from_value(request["deviceCredentials"]["encCredentials"].clone())
            .expect("an envelope");
    let bundle = decrypt_credential_bundle(&encrypted, &device_key)
        .expect("the device key opens what the server holds");
    assert_eq!(
        bundle.srpx.as_str(),
        "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"
    );
    assert_eq!(
        bundle.auk.k.as_str(),
        "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM"
    );

    stored
}

#[tokio::test]
async fn a_returning_device_signs_in_with_its_stored_credentials() {
    let local = vectors().local;
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    server
        .mock_sso_start(json!({
            "userUuid": USER_UUID,
            "accountUuid": ACCOUNT_UUID,
            "keyId": STORED_KEY_ID,
        }))
        .await;
    server
        .mock_sso_verify(verify_response(
            "found",
            Some(&local.encrypted_credential_bundle),
        ))
        .await;
    let storage = RecordingStorage::holding(USER_UUID, &local.local_user_info_json);
    let ui = ScriptedUser::signing_in();

    let (session, master_key) = sign_in(&server, &ui, &storage)
        .await
        .expect("the device signs in");

    assert_downloads_the_account(session, master_key).await;
    assert!(ui.enrollments().is_empty());
    assert!(server.device_credentials().is_empty());
    assert!(storage.writes().is_empty());
    assert!(
        !server
            .requested_paths()
            .await
            .iter()
            .any(|path| path.contains("enrollments"))
    );
    server.mock.verify().await;
}

#[tokio::test]
async fn a_new_device_is_enrolled_and_its_credentials_are_committed() {
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    server.mock_sso_start(json!({"userUuid": USER_UUID})).await;
    server
        .mock_sso_verify(verify_response("device_not_enrolled", None))
        .await;
    mock_enrollment(&server).await;
    let storage = RecordingStorage::default();
    let ui = ScriptedUser::signing_in();

    let (session, master_key) = sign_in(&server, &ui, &storage)
        .await
        .expect("the device is enrolled and signs in");

    assert_downloads_the_account(session, master_key).await;
    assert_eq!(ui.enrollments(), [SsoEnrollmentResult::Success]);
    assert_committed(&server, &storage).await;
    assert_eq!(storage.writes().len(), 1);
    server.mock.verify().await;
}

#[tokio::test]
async fn credentials_that_do_not_decrypt_are_replaced_by_enrolling_again() {
    let old_record = stored_record(USER_UUID, "OLDKEY");
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    server
        .mock_sso_start(json!({
            "userUuid": USER_UUID,
            "accountUuid": ACCOUNT_UUID,
            "keyId": "OLDKEY",
        }))
        .await;
    // The server knows the device, but the key in storage is not the one that encrypted these.
    server
        .mock_sso_verify(verify_response(
            "found",
            Some(&vectors().local.encrypted_credential_bundle),
        ))
        .await;
    mock_enrollment(&server).await;
    let storage = RecordingStorage::holding(USER_UUID, &old_record);
    let ui = ScriptedUser::signing_in();

    let (session, master_key) = sign_in(&server, &ui, &storage)
        .await
        .expect("the device is enrolled and signs in");

    assert_downloads_the_account(session, master_key).await;
    assert_eq!(ui.enrollments(), [SsoEnrollmentResult::Success]);
    let stored = assert_committed(&server, &storage).await;
    assert_ne!(
        stored.credentials_encryption_key_id.as_deref(),
        Some("OLDKEY")
    );
    assert_ne!(
        storage.credentials(USER_UUID).as_deref(),
        Some(old_record.as_str())
    );
    server.mock.verify().await;
}

#[tokio::test]
async fn nothing_is_stored_when_the_server_refuses_the_device_credentials() {
    let server = FakeServer::start_with_commit_answer(json!({"success": 0})).await;
    server.mock_login_info(true).await;
    server.mock_sso_start(json!({"userUuid": USER_UUID})).await;
    server
        .mock_sso_verify(verify_response("device_not_enrolled", None))
        .await;
    mock_enrollment(&server).await;
    let storage = RecordingStorage::default();
    let ui = ScriptedUser::signing_in();

    let error = sign_in(&server, &ui, &storage).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains("device credentials")),
        "unexpected result: {error:?}"
    );
    assert_eq!(server.device_credentials().len(), 1);
    assert_eq!(storage.credentials(USER_UUID), None);
}

#[tokio::test]
async fn a_record_of_another_user_under_this_users_name_is_ignored_and_kept() {
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    // Only the user goes along, the ids of the stored record do not.
    server.mock_sso_start(json!({"userUuid": USER_UUID})).await;
    let other_record = stored_record("SOMEONE_ELSE", STORED_KEY_ID);
    let storage = RecordingStorage::holding(USER_UUID, &other_record);
    let ui = ScriptedUser::giving_up();

    let error = sign_in(&server, &ui, &storage).await.err();

    assert!(matches!(error, Some(OnePasswordError::Canceled(_))));
    assert!(storage.writes().is_empty());
    assert_eq!(
        storage.credentials(USER_UUID).as_deref(),
        Some(other_record.as_str())
    );
    server.mock.verify().await;
}

#[tokio::test]
async fn enrolling_leaves_the_record_of_another_user_in_the_storage() {
    let other_record = stored_record("SOMEONE_ELSE", STORED_KEY_ID);
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    server.mock_sso_start(json!({"userUuid": USER_UUID})).await;
    server
        .mock_sso_verify(verify_response("device_not_enrolled", None))
        .await;
    mock_enrollment(&server).await;
    let storage = RecordingStorage::holding("SOMEONE_ELSE", &other_record);
    let ui = ScriptedUser::signing_in();

    sign_in(&server, &ui, &storage)
        .await
        .expect("the device is enrolled and signs in");

    assert_committed(&server, &storage).await;
    assert_eq!(
        storage.credentials("SOMEONE_ELSE").as_deref(),
        Some(other_record.as_str())
    );
    assert_eq!(storage.writes().len(), 1);
}

#[tokio::test]
async fn a_storage_that_cannot_be_read_fails_the_login_before_the_browser_step() {
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    let storage = RecordingStorage::failing_loads();
    let ui = ScriptedUser::signing_in();

    let error = sign_in(&server, &ui, &storage).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::SecureStorage(what)) if what == "the keychain is locked"),
        "unexpected result: {error:?}"
    );
    assert_eq!(server.requested_paths().await, ["/api/v2/auth/methods"]);
    assert!(ui.enrollments().is_empty());
    assert!(storage.writes().is_empty());
    server.mock.verify().await;
}

#[tokio::test]
async fn a_storage_that_cannot_be_written_fails_the_login() {
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    server.mock_sso_start(json!({"userUuid": USER_UUID})).await;
    server
        .mock_sso_verify(verify_response("device_not_enrolled", None))
        .await;
    mock_enrollment(&server).await;
    let storage = RecordingStorage::failing_stores();
    let ui = ScriptedUser::signing_in();

    let error = sign_in(&server, &ui, &storage).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::SecureStorage(what)) if what == "the disk is full"),
        "unexpected result: {error:?}"
    );
    assert_eq!(server.device_credentials().len(), 1);
    assert_eq!(storage.credentials(USER_UUID), None);
}

#[tokio::test]
async fn a_second_factor_after_the_sso_login_is_unsupported() {
    let server = FakeServer::start_with_mfa(json!({"totp": {"enabled": true}})).await;
    server.mock_login_info(true).await;
    server.mock_sso_start(json!({"userUuid": USER_UUID})).await;
    server
        .mock_sso_verify(verify_response("device_not_enrolled", None))
        .await;
    mock_enrollment(&server).await;
    let storage = RecordingStorage::default();
    let ui = ScriptedUser::signing_in();

    let error = sign_in(&server, &ui, &storage).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::Unsupported(what)) if what.contains("two-factor")),
        "unexpected result: {error:?}"
    );
    assert!(server.device_credentials().is_empty());
    assert!(storage.writes().is_empty());
}

#[tokio::test]
async fn giving_up_at_the_identity_provider_cancels_the_login() {
    let server = FakeServer::start().await;
    server.mock_login_info(true).await;
    server.mock_sso_start(json!({"userUuid": USER_UUID})).await;
    let storage = RecordingStorage::default();
    let ui = ScriptedUser::giving_up();

    let error = sign_in(&server, &ui, &storage).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::Canceled(_))),
        "unexpected result: {error:?}"
    );
    assert_eq!(
        server.requested_paths().await,
        ["/api/v2/auth/methods", "/api/v3/auth/sso/oidc/start"]
    );
    assert!(ui.enrollments().is_empty());
    server.mock.verify().await;
}

#[tokio::test]
async fn an_account_without_the_sso_method_is_unsupported() {
    let server = FakeServer::start().await;
    server.mock_login_info(false).await;
    let storage = RecordingStorage::default();
    let ui = ScriptedUser::signing_in();

    let error = sign_in(&server, &ui, &storage).await.err();

    assert!(
        matches!(&error, Some(OnePasswordError::Unsupported(what)) if what.contains(USERNAME)),
        "unexpected result: {error:?}"
    );
    assert_eq!(server.requested_paths().await, ["/api/v2/auth/methods"]);
    assert!(storage.writes().is_empty());
    server.mock.verify().await;
}

#[tokio::test]
async fn opening_an_account_checks_the_credentials_before_any_request() {
    let client = Client::new(new_http_client());
    let storage = RecordingStorage::default();
    let ui = ScriptedUser::giving_up();

    let mut blank_username = credentials();
    blank_username.username = " ".into();
    let mut bad_address = credentials();
    bad_address.sign_in_address.subdomain = "evil.com/x".into();

    for (credentials, expected) in [
        (blank_username, "username"),
        (bad_address, "sign-in address"),
    ] {
        let error = client
            .open_account_sso(credentials, &ui, &storage)
            .await
            .err();

        assert!(
            matches!(&error, Some(error) if error.to_string().contains(expected)),
            "unexpected result: {error:?}"
        );
    }
    assert!(storage.writes().is_empty());
}

/// An import runs the login on a task of its own.
#[test]
fn the_login_can_run_on_another_thread() {
    fn assert_send<T: Send>(_: &T) {}

    let client = Client::new(new_http_client());
    let storage = RecordingStorage::default();
    let ui = ScriptedUser::giving_up();

    assert_send(&client.open_account_sso(credentials(), &ui, &storage));
}
