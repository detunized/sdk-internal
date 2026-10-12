//! Enrolling this device as a trusted one: ask the server to start an enrollment, wait for the user
//! to approve it on an enrolled device, then take the credentials that device shares.
//!
//! The UI drives the enrollment through an `SsoEnrollmentContext`, which shows the progress, asks
//! for the verification code and can cancel at any point.

use std::pin::pin;

use bitwarden_threading::time;
use futures::future::{Either, select};
use reqwest::StatusCode;
use serde_json::json;
use zeroize::Zeroizing;

use super::{
    super::{
        error::OnePasswordError,
        rest::RestClient,
        wire::{self, CredentialBundle},
    },
    ENROLLMENT_POLL_ATTEMPTS, ENROLLMENT_POLL_INTERVAL,
    cpace::perform_cpace,
    ui::{
        EnrollmentStatus, SsoEnrollmentContext, SsoEnrollmentResult, SsoUi, VerificationCodeResult,
    },
};

/// What the server reports about an enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerStatus {
    /// The user has not picked an enrolled device to approve the request yet.
    SelectingVerifier,
    /// An enrolled device approved the request and shows the verification code.
    WaitingForCode,
    /// The user denied the request on the enrolled device.
    Denied,
    /// Anything else the server may report.
    Unknown,
}

impl ServerStatus {
    fn parse(status: &str) -> ServerStatus {
        match status {
            "SELECTING_VERIFIER" => ServerStatus::SelectingVerifier,
            "WAITING_FOR_CODE" => ServerStatus::WaitingForCode,
            _ => ServerStatus::Unknown,
        }
    }
}

/// Why an enrollment ended early. It also decides what `end_enrollment` reports.
enum Stop {
    Canceled,
    Denied,
    Failed(OnePasswordError),
}

impl From<OnePasswordError> for Stop {
    fn from(error: OnePasswordError) -> Stop {
        Stop::Failed(error)
    }
}

impl From<Stop> for OnePasswordError {
    fn from(stop: Stop) -> OnePasswordError {
        match stop {
            Stop::Canceled => OnePasswordError::Canceled,
            Stop::Denied => OnePasswordError::Denied,
            Stop::Failed(error) => error,
        }
    }
}

/// Enrolls this device and returns the credential bundle an enrolled device shared.
///
/// The context is closed with `end_enrollment` when this ends, unless the future is dropped first.
/// An enrollment that is canceled, from the UI or at the verification code prompt, or that fails
/// after the server handed out its uuid is also canceled on the server, so the approving device
/// stops waiting.
pub(super) async fn enroll_device(
    username: &str,
    sign_in_address: &str,
    sign_in_token: &str,
    ui: &dyn SsoUi,
    rest: &RestClient,
) -> Result<CredentialBundle, OnePasswordError> {
    let context = ui.begin_sso_enrollment().await;
    let context = &*context;
    let mut enrollment_uuid = None;

    // Checking the cancellation first makes it win a tie.
    let outcome = {
        let cancelled = pin!(context.cancelled());
        let enrollment = pin!(enroll(
            username,
            sign_in_address,
            sign_in_token,
            context,
            rest,
            &mut enrollment_uuid,
        ));
        match select(cancelled, enrollment).await {
            Either::Left(_) => Err(Stop::Canceled),
            Either::Right((outcome, _)) => outcome,
        }
    };

    let result = match &outcome {
        Ok(_) => SsoEnrollmentResult::Success,
        Err(Stop::Canceled) => SsoEnrollmentResult::Canceled,
        Err(Stop::Denied) => SsoEnrollmentResult::Denied,
        Err(Stop::Failed(_)) => SsoEnrollmentResult::Failed,
    };

    // A denied enrollment is already over on the server.
    if matches!(outcome, Err(Stop::Canceled | Stop::Failed(_)))
        && let Some(enrollment_uuid) = &enrollment_uuid
    {
        cancel_enrollment(sign_in_token, enrollment_uuid, rest).await;
    }
    context.end_enrollment(result).await;

    outcome.map_err(OnePasswordError::from)
}

/// The steps of the enrollment. The uuid goes to `started` as soon as the server hands it out, for
/// the caller to cancel the enrollment should this be dropped halfway.
async fn enroll(
    username: &str,
    sign_in_address: &str,
    sign_in_token: &str,
    context: &dyn SsoEnrollmentContext,
    rest: &RestClient,
    started: &mut Option<String>,
) -> Result<CredentialBundle, Stop> {
    // Starting signals the enrolled devices to prepare for handing the credentials over.
    context
        .update_status(
            EnrollmentStatus::WaitingForApproval,
            "Waiting for approval from enrolled device...",
        )
        .await;
    let enrollment_uuid = started.insert(start_enrollment(sign_in_token, rest).await?);

    // The user has to press "Transfer key" on one of the enrolled devices.
    let status = poll_status_until_done(
        &[ServerStatus::SelectingVerifier],
        sign_in_token,
        enrollment_uuid,
        rest,
    )
    .await?;
    if valid_status(status)? != ServerStatus::WaitingForCode {
        return Err(unknown_status(status));
    }

    // The enrolled device shows the verification code. Polling on makes denying it there
    // noticed while the user types.
    let verification_code = {
        let user_input = pin!(context.provide_verification_code());
        let poll = pin!(poll_status_until_done(
            &[ServerStatus::WaitingForCode],
            sign_in_token,
            enrollment_uuid,
            rest,
        ));
        match select(user_input, poll).await {
            Either::Left((VerificationCodeResult::Code(code), _)) => Zeroizing::new(code),
            Either::Left((VerificationCodeResult::Cancel, _)) => return Err(Stop::Canceled),
            // Nothing but the user is supposed to end the wait.
            Either::Right((polled, _)) => return Err(unknown_status(valid_status(polled?)?)),
        }
    };

    context
        .update_status(
            EnrollmentStatus::ExchangingCredentials,
            "Exchanging credentials securely",
        )
        .await;
    let credential_bundle = perform_cpace(
        username,
        sign_in_address,
        sign_in_token,
        enrollment_uuid,
        &verification_code,
        rest,
    )
    .await?;

    context
        .update_status(EnrollmentStatus::Completing, "Completing enrollment")
        .await;
    Ok(credential_bundle)
}

/// Denial ends the enrollment, any other status is up to the caller.
fn valid_status(status: ServerStatus) -> Result<ServerStatus, Stop> {
    match status {
        ServerStatus::Denied => Err(Stop::Denied),
        status => Ok(status),
    }
}

/// A status that nothing expects at this point.
fn unknown_status(status: ServerStatus) -> Stop {
    Stop::Failed(OnePasswordError::Internal(format!(
        "device enrollment failed with unknown status {status:?}"
    )))
}

/// Starts an enrollment and returns its uuid.
async fn start_enrollment(
    sign_in_token: &str,
    rest: &RestClient,
) -> Result<String, OnePasswordError> {
    let info: wire::SsoEnrollInfo = rest
        .post_json(
            "v3/device/enrollments",
            json!({ "signInToken": sign_in_token }),
        )
        .await?;

    Ok(info.enrollment_uuid)
}

/// Tells the server to drop the enrollment, so the enrolled devices stop waiting on it. Errors
/// are ignored: there is nothing left to do about them.
async fn cancel_enrollment(sign_in_token: &str, enrollment_uuid: &str, rest: &RestClient) {
    let _ = rest
        .delete_json(
            "v2/device/enrollments",
            json!({
                "enrollmentUuid": enrollment_uuid,
                "signInToken": sign_in_token,
            }),
        )
        .await;
}

/// Polls the status until it is one not in `ignore`.
async fn poll_status_until_done(
    ignore: &[ServerStatus],
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<ServerStatus, OnePasswordError> {
    for _ in 0..ENROLLMENT_POLL_ATTEMPTS {
        let status = get_enrollment_status(sign_in_token, enrollment_uuid, rest).await?;
        if !ignore.contains(&status) {
            return Ok(status);
        }

        time::sleep(ENROLLMENT_POLL_INTERVAL).await;
    }

    Err(OnePasswordError::Internal(
        "device enrollment timed out".into(),
    ))
}

/// Reads the status of the enrollment.
async fn get_enrollment_status(
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<ServerStatus, OnePasswordError> {
    // Denying the request makes the server answer 404, whatever the body.
    let response: Option<wire::SsoEnrollStatus> = rest
        .post_json_unless_status(
            "v3/device/enrollments/status",
            json!({
                "signInToken": sign_in_token,
                "enrollmentUuid": enrollment_uuid,
            }),
            StatusCode::NOT_FOUND,
        )
        .await?;

    Ok(response.map_or(ServerStatus::Denied, |response| {
        ServerStatus::parse(&response.status)
    }))
}
