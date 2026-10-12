//! Login with single sign-on: enroll this device with the approval of an enrolled one, then sign in
//! with the credentials it hands over.

use std::time::Duration;

use serde_json::json;
use url::{Url, form_urlencoded};
use zeroize::Zeroizing;

use self::{
    enrollment::enroll_device,
    ui::{SsoLoginResult, SsoUi},
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
    wire::{AuthComplete, LoginInfo, NewSession, SsoLoginUrl, SsoSession},
};

mod cpace;
mod enrollment;
pub mod ui;

const OIDC_METHOD: &str = "OIDC";
const SSO_START_ENDPOINT: &str = "v3/auth/sso/oidc/start";
const SSO_VERIFY_ENDPOINT: &str = "v3/auth/sso/oidc/verify";
const DEVICE_NOT_ENROLLED: &str = "device_not_enrolled";

/// Delay before retrying a request of `post_json_until_result`, which the server answered with
/// 200 and an empty body.
const UNTIL_RESULT_DELAY: Duration = Duration::from_millis(500);
/// Maximum number of attempts of such a request before it fails.
const UNTIL_RESULT_ATTEMPTS: u32 = 20;
/// Delay between two polls of the enrollment status. The 1Password web client polls every
/// 2 seconds.
const ENROLLMENT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// The number of polls before the enrollment times out, 5 minutes' worth.
const ENROLLMENT_POLL_ATTEMPTS: u32 = 150;

/// Signs in with single sign-on. Returns the signed session and the account unlock key that opens
/// the account's keysets.
///
/// The device is always new to the account, so the user approves it on an enrolled device through
/// `ui`.
pub(super) async fn sso_login(
    credentials: &SsoCredentials,
    client_info: &ClientInfo,
    ui: &dyn SsoUi,
    rest: &RestClient,
) -> Result<(Session, Zeroizing<Vec<u8>>), OnePasswordError> {
    // 1. Get the login info to find out if SSO is available and where its API is.
    let login_info = fetch_auth_methods(&credentials.username, rest).await?;

    // 2. Refuse an account that does not sign in with SSO.
    let account = require_sso(&login_info, &credentials.username)?;

    // 3. From here on the requests go to the SSO API of the account.
    let sso_rest = rest.with_base_url(account.api_url());

    // 4. The server names the identity provider page to send the user to.
    let sso_login_url = start_sso_login(&account, &sso_rest).await?;

    // 5. The user signs in at the identity provider, which redirects back with a code.
    let (code, state) = perform_sso_login(&sso_login_url, ui).await?;

    // 6. The server trades the code for an SSO session and a sign-in token.
    let sso_session = verify_sso_login(&code, &state, client_info, &sso_rest).await?;

    // 7. The requests that follow belong to this SSO session.
    let sso_rest = sso_rest.with_session_id(&sso_session.user.session_uuid)?;

    // 8. The server has not seen this device.
    require_new_device(&sso_session)?;

    // 9. The user approves the device on an enrolled one, which hands over the credential bundle.
    let sign_in_token = sso_session.sso_auth.sign_in_token_details.token.as_str();
    let bundle = enroll_device(
        &credentials.username,
        &account.sign_in_address,
        sign_in_token,
        ui,
        &sso_rest,
    )
    .await?;

    // 10. The bundle holds the SRP x that signs in without a password.
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

    // 11. The account unlock key plays the role of the master key.
    Ok((Session::new(session_key, session_rest), master_key))
}

/// What an SSO login needs from the login info of the account.
struct SsoAccount {
    user_uuid: String,
    /// The address the SSO endpoints are at, as the server sent it. The enrollment key exchange
    /// hashes it verbatim.
    sign_in_address: String,
}

impl SsoAccount {
    /// The root of the SSO API.
    fn api_url(&self) -> String {
        format!("{}/api", self.sign_in_address.trim_end_matches('/'))
    }
}

/// Checks that the account signs in with SSO and that its login info says who the user is and
/// where the SSO endpoints are.
fn require_sso(login_info: &LoginInfo, username: &str) -> Result<SsoAccount, OnePasswordError> {
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
        url.scheme() == "https"
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
/// only https will do.
fn is_web_url(url: &str) -> bool {
    Url::parse(url).is_ok_and(|url| url.scheme() == "https" && url.has_host())
}

/// Asks for the URL of the identity provider login.
async fn start_sso_login(
    account: &SsoAccount,
    rest: &RestClient,
) -> Result<String, OnePasswordError> {
    let response: SsoLoginUrl = rest
        .post_json(SSO_START_ENDPOINT, json!({ "userUuid": account.user_uuid }))
        .await?;
    Ok(response.auth_redirect)
}

/// Has the user log in with the identity provider, and returns the authorization code and the
/// state it redirects back with.
async fn perform_sso_login(
    sso_login_url: &str,
    ui: &dyn SsoUi,
) -> Result<(String, String), OnePasswordError> {
    // Neither URL is echoed in the errors: they carry the state.
    if !is_web_url(sso_login_url) {
        return Err(OnePasswordError::Internal(
            "the SSO login URL is not an https URL".into(),
        ));
    }

    let redirect_to = url_parameter(sso_login_url, "redirect_uri").ok_or_else(|| {
        OnePasswordError::Internal("no redirect_uri found in the SSO login URL".into())
    })?;
    if !is_web_url(&redirect_to) {
        return Err(OnePasswordError::Internal(
            "the SSO redirect URI is not an https URL".into(),
        ));
    }

    let redirected_to = match ui.perform_sso_login(sso_login_url, &redirect_to).await {
        SsoLoginResult::RedirectedTo(url) => url,
        SsoLoginResult::Cancel => return Err(OnePasswordError::Canceled),
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
async fn verify_sso_login(
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

/// A device with a fresh id cannot be known to the server, so anything but `device_not_enrolled`
/// is unexpected.
fn require_new_device(session: &SsoSession) -> Result<(), OnePasswordError> {
    if session.state != DEVICE_NOT_ENROLLED {
        return Err(OnePasswordError::Internal(format!(
            "unexpected SSO session state: {}",
            session.state
        )));
    }
    Ok(())
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

/// The form-decoded value of the first parameter called `name` in the query or the fragment of
/// `url`, as OAuth encodes the redirect. A missing or empty value is `None`.
fn url_parameter(url: &str, name: &str) -> Option<String> {
    let (url, fragment) = url.split_once('#').unwrap_or((url, ""));
    let query = url.split_once('?').map_or("", |(_, query)| query);

    [query, fragment]
        .into_iter()
        .flat_map(|part| form_urlencoded::parse(part.as_bytes()))
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
}
