//! Login with single sign-on: enroll or restore a trusted device, then sign in with the
//! credentials it provides.

use std::{borrow::Cow, time::Duration};

use percent_encoding::percent_decode_str;
use serde_json::json;
use url::Url;
use zeroize::Zeroizing;

use self::{
    enrollment::enroll_device,
    local::{
        decrypt_credential_bundle, derive_device_key, encrypt_credential_bundle,
        encrypt_for_storage, generate_device_key_derivation, load_and_derive_device_key,
        load_local_credentials, store_local_credentials,
    },
    ui::{SecureStorage, SsoLoginResult, SsoUi},
};
use super::{
    credentials::SsoCredentials,
    device::ClientInfo,
    error::OnePasswordError,
    login::{AUTH_COMPLETE_ENDPOINT, AUTH_START_ENDPOINT, fetch_auth_methods},
    mac::MacSigner,
    opdata::{AesKey, decode64_loose},
    rest::RestClient,
    session::Session,
    srp::perform_and_verify_with_x,
    wire::{
        AuthComplete, CredentialBundle, LocalUserInfo, LoginInfo, NewSession, SsoLoginUrl,
        SsoSession, SuccessStatus,
    },
};

mod cpace;
mod enrollment;
#[cfg(test)]
mod fake_server;
#[cfg(test)]
mod flow_tests;
mod local;
#[cfg(test)]
mod test_support;
pub mod ui;

const OIDC_METHOD: &str = "OIDC";
const SSO_START_ENDPOINT: &str = "v3/auth/sso/oidc/start";
const SSO_VERIFY_ENDPOINT: &str = "v3/auth/sso/oidc/verify";
const DEVICE_NOT_ENROLLED: &str = "device_not_enrolled";
const DEVICE_FOUND: &str = "found";
const DEVICE_CREDENTIALS_ENDPOINT: &str = "v3/user/devicecredentials";

/// The timing knobs of the SSO network flows, grouped so the tests can shrink them.
pub(super) struct Timing {
    /// Delay before retrying a request of `post_json_until_result`, which the server answered
    /// with 200 and an empty body.
    pub(super) until_result_delay: Duration,
    /// Maximum number of attempts of such a request before it fails.
    pub(super) until_result_attempts: u32,
    /// Delay between two polls of the enrollment status. The 1Password web client polls every
    /// 2 seconds.
    pub(super) enrollment_poll_interval: Duration,
    /// How long the enrollment status is polled before the enrollment times out.
    pub(super) enrollment_poll_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            until_result_delay: Duration::from_millis(500),
            until_result_attempts: 20,
            enrollment_poll_interval: Duration::from_secs(2),
            enrollment_poll_timeout: Duration::from_secs(5 * 60),
        }
    }
}

/// Signs in with single sign-on. Returns the signed session and the account unlock key that opens
/// the account's keysets.
///
/// The device is enrolled unless the server knows it and the credentials it keeps for it can be
/// restored with the device key in `storage`. Enrolling takes the user through `ui`, and leaves a
/// new device key in `storage` for the next login.
///
/// The record of each user has a name of its own in `storage`, so one storage serves several
/// accounts. A storage that fails to read or write fails the login.
pub(super) async fn sso_login(
    credentials: &SsoCredentials,
    client_info: &ClientInfo,
    ui: &dyn SsoUi,
    storage: &dyn SecureStorage,
    rest: &RestClient,
    timing: &Timing,
) -> Result<(Session, Zeroizing<Vec<u8>>), OnePasswordError> {
    // 1. Get the login info to find out if SSO is available and where its API is.
    let login_info = fetch_auth_methods(&credentials.username, rest).await?;

    // 2. Refuse an account that does not sign in with SSO.
    let account = require_sso(&login_info, &credentials.username)?;

    // 3. What an earlier enrollment of this device left for this user, if anything.
    let local = load_local_credentials(storage, &account.user_uuid)
        .await?
        .unwrap_or_default();

    // 4. From here on the requests go to the SSO API of the account.
    let sso_rest = rest.with_base_url(account.api_url());

    // 5. The server names the identity provider page to send the user to.
    let sso_login_url = start_sso_login(&account, &local, &sso_rest).await?;

    // 6. The user signs in at the identity provider, which redirects back with a code.
    let (code, state) = perform_sso_login(&sso_login_url, ui).await?;

    // 7. The server trades the code for an SSO session and a sign-in token.
    let sso_session = verify_sso_login(&code, &state, client_info, &sso_rest).await?;

    // 8. The requests that follow belong to this SSO session.
    let sso_rest = sso_rest.with_session_id(&sso_session.user.session_uuid)?;

    // 9. The server says whether it has seen this device before.
    let device = device_state(&sso_session)?;

    // 10. Restore the credentials of a known device, which the server keeps encrypted with the
    //     device key.
    let restored = match device {
        DeviceState::Found => restore_credentials(&sso_session, &local),
        DeviceState::NotEnrolled => None,
    };

    // 11. A new device, or one that cannot open its credentials, gets approved by the user on an
    //     enrolled device.
    let (bundle, enrollment_uuid) = match restored {
        Some(bundle) => (bundle, None),
        None => {
            let sign_in_token = sso_session.sso_auth.sign_in_token_details.token.as_str();
            let (bundle, enrollment_uuid) = enroll_device(
                &credentials.username,
                &account.sign_in_address,
                sign_in_token,
                ui,
                &sso_rest,
                timing,
            )
            .await?;
            (bundle, Some(enrollment_uuid))
        }
    };

    // 12. The bundle holds the SRP x that signs in without a password.
    let srp_x = Zeroizing::new(decode64_loose(&bundle.srpx)?);
    let master_key = Zeroizing::new(decode64_loose(&bundle.auk.k)?);
    let (session_key, session_rest) = login(
        &credentials.username,
        &account,
        client_info,
        &sso_session,
        &srp_x,
        &sso_rest,
    )
    .await?;

    // 13. The credentials of a new device only exist in memory so far, keep them for the next
    //     login.
    if let Some(enrollment_uuid) = enrollment_uuid {
        commit_device(
            &sso_session,
            &enrollment_uuid,
            &bundle,
            storage,
            &session_key,
            &session_rest,
        )
        .await?;
    }

    // 14. The account unlock key plays the role of the master key.
    Ok((Session::new(session_key, session_rest), master_key))
}

/// What an SSO login needs from the login info of the account.
pub(super) struct SsoAccount {
    pub(super) user_uuid: String,
    /// The address the SSO endpoints are at, as the server sent it. The enrollment key exchange
    /// hashes it verbatim.
    pub(super) sign_in_address: String,
}

impl SsoAccount {
    /// The root of the SSO API.
    pub(super) fn api_url(&self) -> String {
        format!("{}/api", self.sign_in_address.trim_end_matches('/'))
    }
}

/// What the server says about this device once the identity provider login is verified.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum DeviceState {
    /// The server does not know the device, so it has to be enrolled.
    NotEnrolled,
    /// The server knows the device and sent the credentials it holds for it.
    Found,
}

/// Checks that the account signs in with SSO and that its login info says who the user is and
/// where the SSO endpoints are.
pub(super) fn require_sso(
    login_info: &LoginInfo,
    username: &str,
) -> Result<SsoAccount, OnePasswordError> {
    if !login_info
        .auth_methods
        .iter()
        .any(|method| method.kind == OIDC_METHOD)
    {
        return Err(OnePasswordError::Unsupported(format!(
            "no SSO login method found for account {username}"
        )));
    }

    let (Some(user_uuid), Some(sign_in_address)) = (
        non_empty(&login_info.user_uuid),
        non_empty(&login_info.sign_in_address),
    ) else {
        return Err(OnePasswordError::Internal(
            "SSO login info is missing userUuid or signInAddress".into(),
        ));
    };
    validate_sign_in_address(sign_in_address)?;

    Ok(SsoAccount {
        user_uuid: user_uuid.to_string(),
        sign_in_address: sign_in_address.to_string(),
    })
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.is_empty())
}

/// The server picks this address and every SSO request goes to it, so it has to be a plain https
/// address the API path can be appended to. The address is not echoed in the error: it can carry
/// credentials.
fn validate_sign_in_address(address: &str) -> Result<(), OnePasswordError> {
    let valid = Url::parse(address).is_ok_and(|url| {
        has_allowed_scheme(&url)
            && url.has_host()
            && url.query().is_none()
            && url.fragment().is_none()
    });
    if !valid {
        return Err(OnePasswordError::Internal(
            "the SSO sign-in address is not an https URL".into(),
        ));
    }
    Ok(())
}

/// Requests to a server supplied URL carry credentials and the user opens one in a browser, so
/// only https will do. The fake servers of the tests have no TLS, hence http under test.
fn has_allowed_scheme(url: &Url) -> bool {
    url.scheme() == "https" || (cfg!(test) && url.scheme() == "http")
}

/// The URL the server sends to open in a browser must be a web address, whatever else it holds.
/// The URL is not echoed in the error: it carries the redirect URI and the state.
fn validate_sso_login_url(sso_login_url: &str) -> Result<(), OnePasswordError> {
    let valid =
        Url::parse(sso_login_url).is_ok_and(|url| has_allowed_scheme(&url) && url.has_host());
    if !valid {
        return Err(OnePasswordError::Internal(
            "the SSO login URL is not an https URL".into(),
        ));
    }
    Ok(())
}

/// Asks for the URL of the identity provider login. The ids of an earlier enrollment on this
/// device go along, when there are any, so the server can tell which credentials to offer.
pub(super) async fn start_sso_login(
    account: &SsoAccount,
    local: &LocalUserInfo,
    rest: &RestClient,
) -> Result<String, OnePasswordError> {
    let mut body = json!({ "userUuid": account.user_uuid });
    for (key, value) in [
        ("accountUuid", &local.account_id),
        ("keyId", &local.credentials_encryption_key_id),
    ] {
        if let Some(value) = value {
            body[key] = json!(value);
        }
    }

    let response: SsoLoginUrl = rest.post_json(SSO_START_ENDPOINT, body).await?;
    Ok(response.auth_redirect)
}

/// Has the user log in with the identity provider, and returns the authorization code and the
/// state it redirects back with.
pub(super) async fn perform_sso_login(
    sso_login_url: &str,
    ui: &dyn SsoUi,
) -> Result<(String, String), OnePasswordError> {
    validate_sso_login_url(sso_login_url)?;

    let redirect_to = url_parameter(sso_login_url, "redirect_uri").ok_or_else(|| {
        OnePasswordError::Internal("no redirect_uri found in the SSO login URL".into())
    })?;

    let redirected_to = match ui.perform_sso_login(sso_login_url, &redirect_to).await {
        SsoLoginResult::RedirectedTo(url) => url,
        SsoLoginResult::Cancel => {
            return Err(OnePasswordError::Canceled(
                "SSO login canceled by the user".into(),
            ));
        }
    };

    // The URL is not echoed in the errors: it carries the authorization code.
    let code = url_parameter(&redirected_to, "code").ok_or_else(|| {
        OnePasswordError::Internal("no code returned from the SSO provider".into())
    })?;
    let state = url_parameter(&redirected_to, "state").ok_or_else(|| {
        OnePasswordError::Internal("no state returned from the SSO provider".into())
    })?;
    Ok((code, state))
}

/// Exchanges the authorization code for an SSO session.
pub(super) async fn verify_sso_login(
    code: &str,
    state: &str,
    client_info: &ClientInfo,
    rest: &RestClient,
) -> Result<SsoSession, OnePasswordError> {
    rest.post_json(
        SSO_VERIFY_ENDPOINT,
        json!({
            "code": code,
            "state": state,
            "device": client_info.sso_verify_device_body(),
        }),
    )
    .await
}

/// Tells whether the server knows this device.
pub(super) fn device_state(session: &SsoSession) -> Result<DeviceState, OnePasswordError> {
    match session.state.as_str() {
        DEVICE_NOT_ENROLLED => Ok(DeviceState::NotEnrolled),
        DEVICE_FOUND => Ok(DeviceState::Found),
        state => Err(OnePasswordError::Internal(format!(
            "unexpected SSO session state: {state}"
        ))),
    }
}

/// Decrypts the credentials the server holds for this device with the device key kept in local
/// storage. Anything that goes wrong means there is nothing to restore, and the caller enrolls the
/// device instead.
pub(super) fn restore_credentials(
    session: &SsoSession,
    local: &LocalUserInfo,
) -> Option<CredentialBundle> {
    let derivation = local.device_key_derivation.as_ref()?;
    let auth = session.auth.as_ref()?;

    let device_key = load_and_derive_device_key(derivation).ok()?;
    decrypt_credential_bundle(&auth.encrypted_credentials, &device_key).ok()
}

/// Signs in with the sign-in token the SSO login earned, proving knowledge of the SRP x from the
/// credential bundle. Returns the session key and a client that signs its requests with it.
///
/// Fails with `Unsupported` when the server asks for a second factor.
async fn login(
    username: &str,
    account: &SsoAccount,
    client_info: &ClientInfo,
    sso_session: &SsoSession,
    srp_x: &[u8],
    rest: &RestClient,
) -> Result<(AesKey, RestClient), OnePasswordError> {
    let sign_in_token = sso_session.sso_auth.sign_in_token_details.token.as_str();

    // 1. Start a new session. The session id of the SSO login stays in use.
    let started = start_auth(
        sign_in_token,
        &client_info.device_uuid,
        &account.user_uuid,
        rest,
    )
    .await?;
    let (Some(key_uuid), Some(auth)) = (started.key_uuid, started.auth) else {
        return Err(OnePasswordError::Internal(format!(
            "missing SRP parameters in the start response, its status is '{}'",
            started.status
        )));
    };

    // 2. Do the regular SRP exchange with the x from the bundle. Only the salt of the parameters is
    //    needed, as nothing is derived from a password.
    let session_key = perform_and_verify_with_x(
        srp_x,
        username,
        &key_uuid,
        &decode64_loose(&auth.salt)?,
        &sso_session.user.session_uuid,
        rest,
    )
    .await?;

    // 3. Sign the following requests with the session key, counting them from 1.
    let signed_rest = rest.with_signer(MacSigner::with_request_id(&session_key, 1));

    // 4. Tell the server which device this is. It may answer by asking for a second factor.
    complete_auth(client_info, sign_in_token, &session_key, &signed_rest).await?;

    Ok((session_key, signed_rest))
}

async fn start_auth(
    sign_in_token: &str,
    device_uuid: &str,
    user_uuid: &str,
    rest: &RestClient,
) -> Result<NewSession, OnePasswordError> {
    rest.post_json(
        AUTH_START_ENDPOINT,
        json!({
            "signInToken": sign_in_token,
            "deviceUuid": device_uuid,
            "userUuid": user_uuid,
        }),
    )
    .await
}

async fn complete_auth(
    client_info: &ClientInfo,
    sign_in_token: &str,
    session_key: &AesKey,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let response: AuthComplete = rest
        .post_encrypted_json(
            AUTH_COMPLETE_ENDPOINT,
            json!({
                "client": client_info.client_id(),
                "signInToken": sign_in_token,
                "device": client_info.sso_complete_device_body(),
            }),
            session_key,
        )
        .await?;

    if response.mfa.is_some() {
        return Err(OnePasswordError::Unsupported(
            "two-factor authentication after SSO is not supported".into(),
        ));
    }
    Ok(())
}

/// Stores the credentials of a newly enrolled device on the server, encrypted with a fresh device
/// key, and keeps that key in local storage.
async fn commit_device(
    sso_session: &SsoSession,
    enrollment_uuid: &str,
    bundle: &CredentialBundle,
    storage: &dyn SecureStorage,
    session_key: &AesKey,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    // 1. The server keeps the credentials, encrypted with a key only this device holds.
    let derivation = generate_device_key_derivation();
    let device_key = derive_device_key(&derivation);
    let encrypted_credentials = encrypt_credential_bundle(bundle, &device_key)?;

    // 2. Give the server the encrypted credentials. Only then does it consider the device enrolled
    //    and stop asking for the enrollment.
    let result: SuccessStatus = rest
        .post_encrypted_json_plain(
            DEVICE_CREDENTIALS_ENDPOINT,
            json!({
                "deviceCredentials": {"encCredentials": encrypted_credentials, "v": 2},
                "keyId": device_key.id,
                "enrollmentUuid": enrollment_uuid,
            }),
            session_key,
        )
        .await?;
    if result.success != 1 {
        return Err(OnePasswordError::Internal(
            "failed to store the device credentials".into(),
        ));
    }

    // 3. Keep the device key for the next login, once the server has the credentials it opens.
    let user = &sso_session.user;
    store_local_credentials(
        storage,
        &user.user_uuid,
        &LocalUserInfo {
            user_id: Some(user.user_uuid.clone()),
            account_id: Some(user.account_uuid.clone()),
            credentials_encryption_key_id: Some(device_key.id.clone()),
            device_key_derivation: Some(encrypt_for_storage(&derivation)?),
        },
    )
    .await
}

/// The percent-decoded value of the first parameter called `name` in the query or the fragment of
/// `url`. A missing, empty or undecodable value is `None`.
///
/// Keys match exactly, so `session_state` is not `state`. Only the escapes are decoded and a `+`
/// stays a plus, like .NET's `Uri.UnescapeDataString` does. Form decoding would make it a space.
fn url_parameter(url: &str, name: &str) -> Option<String> {
    let (url, fragment) = url.split_once('#').unwrap_or((url, ""));
    let query = url.split_once('?').map_or("", |(_, query)| query);

    let raw = [query, fragment]
        .into_iter()
        .flat_map(|part| part.split('&'))
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then_some(value)
        })?;

    percent_decode_str(raw)
        .decode_utf8()
        .ok()
        .filter(|value| !value.is_empty())
        .map(Cow::into_owned)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use serde_json::json;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::{
        super::wire::EncryptedEnvelope,
        fake_server::{client_info, verify_response},
        local::{encrypt_for_storage, generate_device_key_derivation},
        test_support::{rest_client, vectors},
        ui::SsoEnrollmentContext,
        *,
    };

    const LOGIN_URL: &str = "https://idp.example.com/authorize?client_id=abc&response_type=code\
        &redirect_uri=https%3A%2F%2Facme.1password.com%2Fsso%2Foidc%2Fredirect%2F&scope=openid";
    const REDIRECT_TO: &str = "https://acme.1password.com/sso/oidc/redirect/";

    /// Plays the identity provider step, and records what it was asked to open.
    struct ScriptedUi {
        result: Mutex<Option<SsoLoginResult>>,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl ScriptedUi {
        fn new(result: SsoLoginResult) -> ScriptedUi {
            ScriptedUi {
                result: Mutex::new(Some(result)),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn redirected_to(url: &str) -> ScriptedUi {
            ScriptedUi::new(SsoLoginResult::RedirectedTo(url.into()))
        }

        fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl SsoUi for ScriptedUi {
        async fn perform_sso_login(
            &self,
            sso_login_url: &str,
            redirect_to: &str,
        ) -> SsoLoginResult {
            self.calls
                .lock()
                .expect("not poisoned")
                .push((sso_login_url.into(), redirect_to.into()));
            self.result
                .lock()
                .expect("not poisoned")
                .take()
                .expect("the login runs once")
        }

        async fn begin_sso_enrollment(&self) -> Box<dyn SsoEnrollmentContext> {
            unreachable!("the login steps never enroll")
        }
    }

    fn login_info(user_uuid: Option<&str>, sign_in_address: Option<&str>) -> LoginInfo {
        serde_json::from_value(json!({
            "userUuid": user_uuid,
            "signInAddress": sign_in_address,
            "authMethods": [
                {"type": "PASSWORD+SK"},
                {"type": "OIDC", "provider": "Acme", "iconUrl": null},
            ],
        }))
        .expect("valid login info")
    }

    fn sso_account() -> SsoAccount {
        require_sso(
            &login_info(Some("USERUUID"), Some("https://acme.1password.com")),
            "user@example.com",
        )
        .expect("an SSO account")
    }

    fn local_user_info() -> LocalUserInfo {
        serde_json::from_str(&vectors().local.local_user_info_json).expect("valid record")
    }

    fn session(state: &str, encrypted_credentials: Option<&EncryptedEnvelope>) -> SsoSession {
        serde_json::from_value(verify_response(state, encrypted_credentials))
            .expect("a valid session")
    }

    fn found_session(encrypted_credentials: &EncryptedEnvelope) -> SsoSession {
        session("found", Some(encrypted_credentials))
    }

    #[test]
    fn requires_the_oidc_method() {
        let mut info = login_info(Some("USERUUID"), Some("https://acme.1password.com"));
        info.auth_methods.retain(|method| method.kind != "OIDC");

        let error = require_sso(&info, "user@example.com").err();

        assert!(
            matches!(&error, Some(OnePasswordError::Unsupported(what)) if what.contains("user@example.com")),
            "unexpected result: {error:?}"
        );
    }

    #[test]
    fn requires_the_user_uuid_and_the_sign_in_address() {
        for (user_uuid, sign_in_address) in [
            (None, Some("https://acme.1password.com")),
            (Some(""), Some("https://acme.1password.com")),
            (Some("USERUUID"), None),
            (Some("USERUUID"), Some("")),
            (None, None),
        ] {
            let error =
                require_sso(&login_info(user_uuid, sign_in_address), "user@example.com").err();

            assert!(
                matches!(error, Some(OnePasswordError::Internal(_))),
                "unexpected result for {user_uuid:?} and {sign_in_address:?}: {error:?}"
            );
        }
    }

    #[test]
    fn accepts_the_login_info_of_an_sso_account() {
        let account = sso_account();

        assert_eq!(account.user_uuid, "USERUUID");
        assert_eq!(account.sign_in_address, "https://acme.1password.com");
        assert_eq!(account.api_url(), "https://acme.1password.com/api");
    }

    #[test]
    fn a_trailing_slash_is_not_doubled_in_the_api_url() {
        let account = require_sso(
            &login_info(Some("USERUUID"), Some("https://acme.1password.com/")),
            "user@example.com",
        )
        .expect("an SSO account");

        assert_eq!(account.sign_in_address, "https://acme.1password.com/");
        assert_eq!(account.api_url(), "https://acme.1password.com/api");
    }

    #[test]
    fn accepts_the_address_forms_of_a_web_server() {
        for address in [
            "https://acme.1password.com",
            "https://acme.1password.com/",
            "http://127.0.0.1:8080",
            "https://sso.example.com:8443/base",
        ] {
            require_sso(
                &login_info(Some("USERUUID"), Some(address)),
                "user@example.com",
            )
            .unwrap_or_else(|error| panic!("'{address}' is rejected: {error}"));
        }
    }

    #[test]
    fn rejects_a_sign_in_address_that_is_not_a_web_address() {
        for address in [
            "acme.1password.com",
            "//acme.1password.com",
            "/api",
            "ftp://acme.1password.com",
            "file://acme.1password.com/api",
            "javascript:alert(1)",
            "mailto:user@example.com",
            "https://",
            "https://acme.1password.com?next=/",
            "https://acme.1password.com/?",
            "https://acme.1password.com#top",
            "https://acme.1password.com/#",
            "not a url",
            "http://user:SECRET@acme.1password.com?next=/",
            "ftp://user:SECRET@acme.1password.com",
        ] {
            let error = require_sso(
                &login_info(Some("USERUUID"), Some(address)),
                "user@example.com",
            )
            .err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if !what.contains(address) && !what.contains("SECRET")),
                "unexpected result for '{address}': {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn start_sends_only_the_user_uuid_without_local_credentials() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v3/auth/sso/oidc/start"))
                    .and(matchers::body_json(json!({"userUuid": "USERUUID"})))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"authRedirect": LOGIN_URL})),
                    )
                    .expect(1),
            )
            .await;

        let url = start_sso_login(
            &sso_account(),
            &LocalUserInfo::default(),
            &rest_client(&server),
        )
        .await
        .expect("starts");

        assert_eq!(url, LOGIN_URL);
        server.verify().await;
    }

    #[tokio::test]
    async fn start_sends_the_stored_ids() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v3/auth/sso/oidc/start"))
                    .and(matchers::body_json(json!({
                        "userUuid": "USERUUID",
                        "accountUuid": "ACCOUNTUUID",
                        "keyId": "m3h6kz4qjbj5xlzp7g2vy3tq4e",
                    })))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"authRedirect": LOGIN_URL})),
                    )
                    .expect(1),
            )
            .await;

        start_sso_login(&sso_account(), &local_user_info(), &rest_client(&server))
            .await
            .expect("starts");

        server.verify().await;
    }

    #[tokio::test]
    async fn start_sends_each_stored_id_on_its_own() {
        let server = MockServer::start().await;
        for (key, value) in [("accountUuid", "ACCOUNTUUID"), ("keyId", "KEYID")] {
            server
                .register(
                    Mock::given(matchers::method("POST"))
                        .and(matchers::path("/api/v3/auth/sso/oidc/start"))
                        .and(matchers::body_json(
                            json!({"userUuid": "USERUUID", key: value}),
                        ))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .set_body_json(json!({"authRedirect": LOGIN_URL})),
                        )
                        .expect(1),
                )
                .await;
        }
        let rest = rest_client(&server);

        let only_account = LocalUserInfo {
            account_id: Some("ACCOUNTUUID".into()),
            ..LocalUserInfo::default()
        };
        let only_key = LocalUserInfo {
            credentials_encryption_key_id: Some("KEYID".into()),
            ..LocalUserInfo::default()
        };
        start_sso_login(&sso_account(), &only_account, &rest)
            .await
            .expect("starts");
        start_sso_login(&sso_account(), &only_key, &rest)
            .await
            .expect("starts");

        server.verify().await;
    }

    #[tokio::test]
    async fn start_returns_a_server_error() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/sso/oidc/start")).respond_with(
                    ResponseTemplate::new(400)
                        .set_body_json(json!({"errorCode": 117, "errorMessage": "gone"})),
                ),
            )
            .await;

        let error = start_sso_login(&sso_account(), &local_user_info(), &rest_client(&server))
            .await
            .err();

        assert!(matches!(error, Some(OnePasswordError::NotFound)));
    }

    #[tokio::test]
    async fn perform_returns_the_code_and_state_of_the_c_example() {
        let redirect = vectors().redirect;
        let ui = ScriptedUi::redirected_to(&redirect.url);

        let (code, state) = perform_sso_login(LOGIN_URL, &ui).await.expect("performs");

        assert_eq!(code, redirect.code);
        assert_eq!(state, redirect.state);
        assert_eq!(
            ui.calls(),
            [(LOGIN_URL.to_string(), REDIRECT_TO.to_string())]
        );
    }

    #[tokio::test]
    async fn perform_reads_the_parameters_from_the_query_too() {
        let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb?code=c0de&state=st4te");

        let (code, state) = perform_sso_login(LOGIN_URL, &ui).await.expect("performs");

        assert_eq!((code.as_str(), state.as_str()), ("c0de", "st4te"));
    }

    #[tokio::test]
    async fn perform_does_not_mistake_session_state_for_state() {
        let ui = ScriptedUi::redirected_to(
            "https://acme.1password.com/cb#session_state=WRONG&code=c0de&state=st4te",
        );

        let (_, state) = perform_sso_login(LOGIN_URL, &ui).await.expect("performs");

        assert_eq!(state, "st4te");
    }

    #[tokio::test]
    async fn perform_requires_a_state_of_its_own() {
        let ui = ScriptedUi::redirected_to(
            "https://acme.1password.com/cb#code=c0de&session_state=WRONG",
        );

        let error = perform_sso_login(LOGIN_URL, &ui).await.err();

        assert!(
            matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains("no state")),
            "unexpected result: {error:?}"
        );
    }

    #[tokio::test]
    async fn perform_decodes_an_escaped_plus_and_keeps_a_literal_one() {
        let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb#code=a%2Bb&state=c+d");

        let (code, state) = perform_sso_login(LOGIN_URL, &ui).await.expect("performs");

        assert_eq!(code, "a+b");
        assert_eq!(state, "c+d");
    }

    #[tokio::test]
    async fn perform_requires_a_code_and_a_state() {
        for (url, missing) in [
            ("https://acme.1password.com/cb#state=st4te", "code"),
            ("https://acme.1password.com/cb#code=&state=st4te", "code"),
            ("https://acme.1password.com/cb#code=c0de", "state"),
            ("https://acme.1password.com/cb#code=c0de&state=", "state"),
            ("https://acme.1password.com/cb", "code"),
            ("https://acme.1password.com/cb#code=%FF&state=st4te", "code"),
        ] {
            let error = perform_sso_login(LOGIN_URL, &ScriptedUi::redirected_to(url))
                .await
                .err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains(&format!("no {missing}"))),
                "unexpected result for '{url}': {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn perform_requires_a_redirect_uri_before_asking_the_user() {
        for login_url in [
            "https://idp.example.com/authorize?client_id=abc",
            "https://idp.example.com/authorize?post_redirect_uri=https%3A%2F%2Fexample.com",
            "https://idp.example.com/authorize?redirect_uri=",
        ] {
            let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb#code=c&state=s");

            let error = perform_sso_login(login_url, &ui).await.err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains("redirect_uri")),
                "unexpected result for '{login_url}': {error:?}"
            );
            assert!(ui.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn perform_rejects_a_login_url_that_is_not_a_web_address() {
        for login_url in [
            "javascript:alert(1)//?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "file://idp.example.com/authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "ftp://idp.example.com/authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "file:///authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "https://?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "//idp.example.com/authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
            "idp.example.com/authorize?redirect_uri=https%3A%2F%2Facme.1password.com&state=SECRET",
        ] {
            let ui = ScriptedUi::redirected_to("https://acme.1password.com/cb#code=c&state=s");

            let error = perform_sso_login(login_url, &ui).await.err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if !what.contains("SECRET")),
                "unexpected result for '{login_url}': {error:?}"
            );
            assert!(ui.calls().is_empty(), "'{login_url}' reached the user");
        }
    }

    #[tokio::test]
    async fn perform_reports_a_cancel_as_canceled() {
        let ui = ScriptedUi::new(SsoLoginResult::Cancel);

        let error = perform_sso_login(LOGIN_URL, &ui).await.err();

        assert!(
            matches!(error, Some(OnePasswordError::Canceled(_))),
            "unexpected result: {error:?}"
        );
        assert_eq!(ui.calls().len(), 1);
    }

    #[test]
    fn url_parameters_match_whole_keys_in_the_query_and_the_fragment() {
        let url = "https://h/p?x_code=1&code=2&y=code=3#z=4&code=5";

        assert_eq!(url_parameter(url, "code").as_deref(), Some("2"));
        assert_eq!(url_parameter(url, "x_code").as_deref(), Some("1"));
        assert_eq!(url_parameter(url, "z").as_deref(), Some("4"));
        assert_eq!(url_parameter(url, "y").as_deref(), Some("code=3"));
        assert_eq!(url_parameter(url, "cod"), None);
        assert_eq!(
            url_parameter("https://h/p#code=5", "code").as_deref(),
            Some("5")
        );
        assert_eq!(
            url_parameter("https://h/p?a&code=1", "code").as_deref(),
            Some("1")
        );
    }

    #[test]
    fn url_parameters_decode_escapes_only() {
        assert_eq!(
            url_parameter("u?a=%E2%9C%93+%2B%3D%26", "a").as_deref(),
            Some("\u{2713}++=&")
        );
    }

    #[tokio::test]
    async fn verify_sends_the_code_state_and_device_descriptor() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v3/auth/sso/oidc/verify"))
                    .and(matchers::body_json(json!({
                        "code": "c0de",
                        "state": "st4te",
                        "device": client_info().sso_verify_device_body(),
                    })))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "type": "device_not_enrolled",
                        "user": {
                            "sessionUuid": "SESSIONUUID",
                            "accountUuid": "ACCOUNTUUID",
                            "userUuid": "USERUUID",
                            "email": "user@example.com",
                        },
                        "ssoAuth": {
                            "signInTokenDetails": {
                                "token": "SIGN_IN_TOKEN",
                                "publicKey": "PUBLICKEY",
                                "exp": "2030-01-01T00:00:00Z",
                            },
                        },
                    })))
                    .expect(1),
            )
            .await;

        let session = verify_sso_login("c0de", "st4te", &client_info(), &rest_client(&server))
            .await
            .expect("verifies");

        assert_eq!(session.state, "device_not_enrolled");
        assert_eq!(session.user.session_uuid, "SESSIONUUID");
        assert_eq!(session.user.account_uuid, "ACCOUNTUUID");
        assert_eq!(session.user.user_uuid, "USERUUID");
        assert_eq!(
            session.sso_auth.sign_in_token_details.token.as_str(),
            "SIGN_IN_TOKEN"
        );
        assert!(session.auth.is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn verify_returns_a_server_error() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/sso/oidc/verify")).respond_with(
                    ResponseTemplate::new(400)
                        .set_body_json(json!({"errorCode": 500, "errorMessage": "bad code"})),
                ),
            )
            .await;

        let error = verify_sso_login("c0de", "st4te", &client_info(), &rest_client(&server))
            .await
            .err();

        assert!(
            matches!(error, Some(OnePasswordError::Internal(what)) if what.contains("bad code"))
        );
    }

    #[test]
    fn the_sign_in_token_stays_out_of_debug_output() {
        let output = format!("{:?}", session("found", None));

        assert!(!output.contains("SIGN_IN_TOKEN"), "leaked: {output}");
    }

    #[test]
    fn a_new_device_is_not_enrolled_and_a_known_one_is_found() {
        assert_eq!(
            device_state(&session("device_not_enrolled", None)).ok(),
            Some(DeviceState::NotEnrolled)
        );
        assert_eq!(
            device_state(&session("found", None)).ok(),
            Some(DeviceState::Found)
        );
    }

    #[test]
    fn any_other_session_state_is_an_error() {
        for state in ["", "Found", "device_deleted", "unknown"] {
            let error = device_state(&session(state, None)).err();

            assert!(
                matches!(&error, Some(OnePasswordError::Internal(what)) if what.contains(state)),
                "unexpected result for '{state}': {error:?}"
            );
        }
    }

    #[test]
    fn restores_the_credentials_from_the_c_written_values() {
        let vectors = vectors().local;
        let session = found_session(&vectors.encrypted_credential_bundle);

        let bundle = restore_credentials(&session, &local_user_info()).expect("restores");

        assert_eq!(
            bundle.srpx.as_str(),
            "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"
        );
        assert_eq!(bundle.auk.kid, "mp");
        assert_eq!(
            bundle.auk.k.as_str(),
            "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM"
        );
    }

    #[test]
    fn restoring_with_another_device_key_gives_none() {
        let other = LocalUserInfo {
            device_key_derivation: Some(
                encrypt_for_storage(&generate_device_key_derivation()).expect("encrypts"),
            ),
            ..local_user_info()
        };
        let session = found_session(&vectors().local.encrypted_credential_bundle);

        assert!(restore_credentials(&session, &other).is_none());
    }

    #[test]
    fn restoring_without_a_derivation_gives_none() {
        let without = LocalUserInfo {
            device_key_derivation: None,
            ..local_user_info()
        };
        let session = found_session(&vectors().local.encrypted_credential_bundle);

        assert!(restore_credentials(&session, &without).is_none());
        assert!(restore_credentials(&session, &LocalUserInfo::default()).is_none());
    }

    #[test]
    fn restoring_without_server_credentials_gives_none() {
        assert!(restore_credentials(&session("found", None), &local_user_info()).is_none());
    }

    #[test]
    fn restoring_from_broken_values_gives_none() {
        let mut tampered = vectors().local.encrypted_credential_bundle;
        tampered.data.replace_range(0..1, "A");
        assert!(restore_credentials(&found_session(&tampered), &local_user_info()).is_none());

        let mut broken_derivation = local_user_info();
        if let Some(derivation) = broken_derivation.device_key_derivation.as_mut() {
            derivation.data.replace_range(0..1, "A");
        }
        let session = found_session(&vectors().local.encrypted_credential_bundle);
        assert!(restore_credentials(&session, &broken_derivation).is_none());
    }
}
