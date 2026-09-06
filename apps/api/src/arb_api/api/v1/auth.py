"""Authentication endpoints (§59, §61, §68).

Mounted under ``/api/v1/auth`` with no ancestor prefix, for the reason explained in
:mod:`arb_api.api.paths`: a prefix declared on a parent router is missing from
``scope["route"].path``, and therefore from every access log line and every
Prometheus ``route`` label.

Two conventions run through the file.

**Cookies are set and cleared in one place.** The refresh token lives in an HttpOnly
cookie scoped to this path prefix, so it is attached to the handful of requests that
can use it and to nothing else; the CSRF token lives in a cookie that is deliberately
*readable*, because a double-submit check requires the client to read one copy and
send it back as a header. Both are cleared on sign-out, since a stale refresh cookie
that the server would reject anyway is still a credential sitting in a browser.

**Failures are raised, not returned.** Every refusal path raises the error class from
:mod:`arb_core.errors`, which the exception handlers turn into the §71 envelope with
the right status and headers. An endpoint that returned a 200 with ``{"ok": false}``
would be an endpoint whose failures no client library notices.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Request, Response, status

from arb_api.api.dependencies import (
    AuthServiceDep,
    ClientIpDep,
    CurrentAuthDep,
    MfaServiceDep,
    PasswordServiceDep,
    RequestIdDep,
    SessionServiceDep,
    SettingsDep,
    UserAgentDep,
)
from arb_api.api.paths import API_V1_PREFIX
from arb_api.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    MfaConfirmRequest,
    MfaDisableRequest,
    MfaEnrollmentResponse,
    MfaLoginRequest,
    MfaStatusResponse,
    PasswordChangeResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    PasswordResetResponse,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    SessionListResponse,
    SessionSummary,
    TokenSet,
    UserSummary,
    VerifyEmailRequest,
)
from arb_api.schemas.common import MessageResponse
from arb_api.services.auth_results import IssuedTokens, LoginOutcome
from arb_core.config import EmailProvider
from arb_core.errors import (
    AuthenticationError,
    InvalidCredentialsError,
    MfaRequiredError,
    NotFoundError,
    ServiceUnavailableError,
)

if TYPE_CHECKING:
    from arb_core.config import Settings
    from arb_persistence.models.auth import User, UserSession

__all__ = ["router"]

router = APIRouter(prefix=f"{API_V1_PREFIX}/auth", tags=["auth"])

#: The three values Starlette's ``set_cookie`` accepts.
_SameSite = Literal["lax", "strict", "none"]

#: The refresh cookie is scoped to the authentication prefix. A cookie that is only
#: sent where it can be used is a cookie that an unrelated endpoint cannot leak, and
#: one that a cross-site request cannot get attached to a trading call.
_COOKIE_PATH: Final[str] = f"{API_V1_PREFIX}/auth"

_CSRF_HEADER: Final[str] = "X-CSRF-Token"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _same_site(settings: Settings) -> _SameSite:
    """Narrow the configured string to what ``set_cookie`` accepts.

    :class:`~arb_core.config.Settings` validates this value when it loads, so by the
    time it is read here it is one of three literals. The cast states that invariant
    instead of re-checking it — and re-checking it here would mean a typo in the
    environment turned into a 500 on every sign-in rather than a startup failure the
    operator would actually see.
    """
    return cast("_SameSite", settings.cookie_samesite)


def _set_session_cookies(response: Response, tokens: IssuedTokens, settings: Settings) -> None:
    """Attach the refresh and CSRF cookies for a freshly issued session."""
    max_age = int(settings.session_absolute_ttl.total_seconds())
    domain = settings.cookie_domain or None
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=tokens.refresh_token,
        max_age=max_age,
        path=_COOKIE_PATH,
        domain=domain,
        secure=settings.cookie_secure,
        httponly=settings.cookie_httponly,
        samesite=_same_site(settings),
    )
    # Not HttpOnly, deliberately: the double-submit check works because JavaScript on
    # this origin can read the cookie and send it back as a header, while a cross-site
    # attacker can do neither. Making it HttpOnly would not make it more secure, it
    # would make the check impossible.
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=tokens.csrf_token,
        max_age=max_age,
        path=_COOKIE_PATH,
        domain=domain,
        secure=settings.cookie_secure,
        httponly=False,
        samesite=_same_site(settings),
    )


def _clear_session_cookies(response: Response, settings: Settings) -> None:
    """Remove both cookies, with the same path and domain they were set with.

    A ``delete_cookie`` call whose path does not match the one used to set it leaves
    the cookie in the browser, and the user is then signed out server-side while still
    presenting a credential — which reads exactly like a broken sign-out.
    """
    domain = settings.cookie_domain or None
    for name in (settings.refresh_cookie_name, settings.csrf_cookie_name):
        response.delete_cookie(key=name, path=_COOKIE_PATH, domain=domain)


def _dev_email_token(settings: Settings) -> bool:
    """Whether a token may be surfaced in a response because nothing can email it.

    True only when email delivery is not configured *and* this is not a deployed
    environment. Both conditions matter: on a deployed environment the token must go
    to the mailbox and never to an HTTP response, because an endpoint that returns a
    password-reset token to whoever asked for one has authenticated nobody.
    """
    return settings.email_provider is EmailProvider.NONE and not settings.is_deployed


def _user_summary(user: User) -> UserSummary:
    """The account, without any of its credential material."""
    return UserSummary(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role.value,
        status=user.status.value,
        email_verified=user.email_verified,
        mfa_enabled=user.mfa_confirmed,
        must_change_password=user.must_change_password,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


def _token_set(tokens: IssuedTokens) -> TokenSet:
    return TokenSet(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        csrf_token=tokens.csrf_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
        session_id=tokens.session_id,
    )


def _session_summary(row: UserSession, *, current: UUID | None) -> SessionSummary:
    return SessionSummary(
        id=row.id,
        created_at=row.created_at,
        last_seen_at=row.last_seen_at,
        expires_at=row.expires_at,
        ip_address=row.ip_address,
        user_agent=row.user_agent,
        mfa_completed_at=row.mfa_completed_at,
        current=current is not None and row.id == current,
    )


def _require_tokens(result_tokens: IssuedTokens | None) -> IssuedTokens:
    """Narrow an authenticated result to its tokens.

    A ``LoginResult`` that claims success without tokens is a programming error in the
    service, not something to paper over with a null check in every endpoint; it is
    reported as a service failure so the client retries rather than storing ``None``
    as a credential.
    """
    if result_tokens is None:
        msg = "sign-in reported success without issuing a credential set"
        raise ServiceUnavailableError(msg)
    return result_tokens


# ---------------------------------------------------------------------------
# Registration and sign-in
# ---------------------------------------------------------------------------
@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account",
    description=(
        "Self-service sign-up. The account is created with a customer role; there is "
        "no field in this request that can confer administrative authority. When the "
        "platform requires email verification the account starts in "
        "`PENDING_VERIFICATION` and cannot sign in until the address is confirmed."
    ),
)
async def register(
    payload: RegisterRequest,
    service: AuthServiceDep,
    settings: SettingsDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> RegisterResponse:
    """Register a new account."""
    result = await service.register(
        email=payload.email,
        password=payload.password,
        display_name=payload.display_name,
        ip_address=ip_address,
        request_id=request_id,
    )
    return RegisterResponse(
        user=_user_summary(result.user),
        requires_email_verification=settings.email_verification_required,
        message=(
            "Account created. Check your email to confirm your address before signing in."
            if settings.email_verification_required
            else "Account created. You can sign in now."
        ),
        dev_verification_token=(result.verification_token if _dev_email_token(settings) else None),
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Sign in with a password",
    description=(
        "Returns a credential set, or a `401 MFA_REQUIRED` carrying a short-lived "
        "challenge when the account has a confirmed second factor. A half-completed "
        "sign-in is never reported as a success. The response to a wrong password and "
        "to an unknown address is identical, so this endpoint cannot be used to "
        "discover which addresses are registered."
    ),
)
async def login(
    payload: LoginRequest,
    response: Response,
    service: AuthServiceDep,
    settings: SettingsDep,
    ip_address: ClientIpDep,
    user_agent: UserAgentDep,
    request_id: RequestIdDep,
) -> LoginResponse:
    """Verify a password and open a session, or issue an MFA challenge."""
    result = await service.login(
        email=payload.email,
        password=payload.password,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
    )
    if result.outcome is LoginOutcome.MFA_REQUIRED:
        # 401, with the challenge in the error details: the caller is not
        # authenticated yet, and a client that only inspects the status code must not
        # be able to mistake this for a completed sign-in.
        raise MfaRequiredError(
            details={
                "mfa_challenge": result.mfa_challenge,
                "expires_in": int(settings.mfa_challenge_ttl.total_seconds()),
            }
        )
    tokens = _require_tokens(result.tokens)
    _set_session_cookies(response, tokens, settings)
    return LoginResponse(user=_user_summary(result.user), tokens=_token_set(tokens))


@router.post(
    "/mfa/login",
    response_model=LoginResponse,
    summary="Complete a sign-in with a second factor",
    description=(
        "Exchanges the `mfa_challenge` from `/auth/login` plus a code from the "
        "authenticator app — or one of the single-use recovery codes — for a full "
        "credential set. The challenge expires in minutes and confers nothing on its "
        "own."
    ),
)
async def login_with_mfa(
    payload: MfaLoginRequest,
    response: Response,
    service: AuthServiceDep,
    settings: SettingsDep,
    ip_address: ClientIpDep,
    user_agent: UserAgentDep,
    request_id: RequestIdDep,
) -> LoginResponse:
    """Finish a sign-in whose password was already correct."""
    result = await service.complete_mfa_login(
        challenge=payload.challenge,
        code=payload.code,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
    )
    tokens = _require_tokens(result.tokens)
    _set_session_cookies(response, tokens, settings)
    return LoginResponse(user=_user_summary(result.user), tokens=_token_set(tokens))


@router.post(
    "/refresh",
    response_model=TokenSet,
    summary="Rotate a refresh token",
    description=(
        "Exchanges a refresh token for a new credential set. The token may arrive in "
        "the request body or in the `arb_refresh` cookie. **The `X-CSRF-Token` header "
        "is required either way**, because a cross-site form can post a JSON-looking "
        "body with a content type that provokes no CORS preflight. Presenting a token "
        "that has already been rotated revokes every session descended from the same "
        "sign-in: reuse is treated as theft, because it is the only reading the server "
        "can defend."
    ),
)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    response: Response,
    service: SessionServiceDep,
    settings: SettingsDep,
    ip_address: ClientIpDep,
    user_agent: UserAgentDep,
    request_id: RequestIdDep,
) -> TokenSet:
    """Rotate the refresh token and re-issue the credential set."""
    # A token in the body wins over the cookie: a client that sends one explicitly is
    # saying which credential to rotate, and a stale cookie must not override it.
    presented = payload.refresh_token or request.cookies.get(settings.refresh_cookie_name)
    if not presented:
        # Nothing to rotate. Reported as an authentication failure rather than a
        # validation error, because from the client's side it simply has no session.
        raise AuthenticationError
    tokens = await service.refresh(
        refresh_token=presented,
        # Read from the header only. Taking it from the cookie would defeat the
        # double-submit check outright: the point is that the client reads one copy
        # and returns it by a channel a cross-site request cannot use.
        csrf_token=request.headers.get(settings.csrf_header_name),
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
    )
    _set_session_cookies(response, tokens, settings)
    return _token_set(tokens)


# ---------------------------------------------------------------------------
# The authenticated caller
# ---------------------------------------------------------------------------
@router.get(
    "/me",
    response_model=UserSummary,
    summary="The signed-in account",
    description=(
        "Read from the database on every call rather than from token claims, so a role "
        "change or a suspension is reflected immediately and not when the access token "
        "next expires."
    ),
)
async def me(auth: CurrentAuthDep) -> UserSummary:
    """Return the caller's own account."""
    return _user_summary(auth.user)


@router.get(
    "/sessions",
    response_model=SessionListResponse,
    summary="Signed-in devices",
    description=(
        "Every session currently valid for this account, most recently used first. "
        "Sessions that have expired or been revoked are not listed. Each entry carries "
        "the address and user agent it was created with, because recognising a session "
        "is the entire point of the list; none carries a credential."
    ),
)
async def list_sessions(auth: CurrentAuthDep, service: SessionServiceDep) -> SessionListResponse:
    """List the caller's active sessions."""
    rows = await service.list_active(user_id=auth.user.id)
    summaries = [_session_summary(row, current=auth.session.id) for row in rows]
    return SessionListResponse(sessions=summaries, count=len(summaries))


@router.delete(
    "/sessions/{session_id}",
    response_model=MessageResponse,
    summary="Sign out one device",
    description=(
        "Revokes a single session belonging to this account. A session id that does "
        "not exist and one that belongs to somebody else produce the same `404`, so "
        "the endpoint cannot be used to confirm that a guessed id is real."
    ),
)
async def revoke_session(
    session_id: UUID,
    auth: CurrentAuthDep,
    service: SessionServiceDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """Revoke one of the caller's own sessions."""
    revoked = await service.revoke_own(
        session_id=session_id,
        user=auth.user,
        reason="USER_LOGOUT",
        ip_address=ip_address,
        request_id=request_id,
    )
    if not revoked:
        raise NotFoundError("no such session")
    return MessageResponse(message="That session has been signed out.")


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Sign out",
    description="Revokes the session making the request and clears its cookies.",
)
async def logout(
    response: Response,
    auth: CurrentAuthDep,
    service: AuthServiceDep,
    settings: SettingsDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """End the caller's current session."""
    await service.logout(
        session_id=auth.session.id,
        user=auth.user,
        ip_address=ip_address,
        request_id=request_id,
    )
    _clear_session_cookies(response, settings)
    return MessageResponse(message="Signed out.")


@router.post(
    "/logout-all",
    response_model=MessageResponse,
    summary="Sign out every other device",
    description=(
        "Revokes every session for this account except the one making the request. "
        "Sparing the caller is what makes this usable during an incident: the person "
        "who suspects their account is compromised is not thrown out mid-response."
    ),
)
async def logout_everywhere(
    auth: CurrentAuthDep,
    service: AuthServiceDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """End every session but this one."""
    revoked = await service.logout_everywhere(
        user=auth.user,
        session_id=auth.session.id,
        ip_address=ip_address,
        request_id=request_id,
    )
    return MessageResponse(message=f"Signed out {revoked} other session(s).")


# ---------------------------------------------------------------------------
# Passwords and email
# ---------------------------------------------------------------------------
@router.post(
    "/password/change",
    response_model=PasswordChangeResponse,
    summary="Change password",
    description=(
        "Requires the current password even from an authenticated caller, because an "
        "open session on an unlocked machine is not proof of who is sitting at it. "
        "**Every** session for the account is revoked, including this one, and a "
        "replacement credential set is returned: a session created before the change "
        "is indistinguishable from one an attacker holds, so the device that made the "
        "change is signed in again with the new credential rather than exempted. "
        "Clients must store the returned tokens and the new cookies."
    ),
)
async def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    auth: CurrentAuthDep,
    service: PasswordServiceDep,
    settings: SettingsDep,
    ip_address: ClientIpDep,
    user_agent: UserAgentDep,
    request_id: RequestIdDep,
) -> PasswordChangeResponse:
    """Replace the caller's password and re-issue this device's session."""
    result = await service.change_password(
        user=auth.user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        session_id=auth.session.id,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
    )
    _set_session_cookies(response, result.tokens, settings)
    return PasswordChangeResponse(
        message=(
            f"Password changed. {result.revoked_sessions} session(s) were signed out and "
            "this device was signed in again with the new password."
        ),
        sessions_revoked=result.revoked_sessions,
        tokens=_token_set(result.tokens),
    )


@router.post(
    "/password/reset",
    response_model=PasswordResetResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a password reset",
    description=(
        "Always accepted with the same response, whether or not the address has an "
        "account, so this cannot be used to enumerate registered addresses. Issuing a "
        "new token invalidates any outstanding one for the same account. **Email "
        "delivery is NOT IMPLEMENTED in this phase**: outside local development the "
        "token has nowhere to go, and the field that would carry it is always null."
    ),
)
async def request_password_reset(
    payload: PasswordResetRequest,
    service: PasswordServiceDep,
    settings: SettingsDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> PasswordResetResponse:
    """Ask for a reset link."""
    token = await service.request_password_reset(
        email=payload.email, ip_address=ip_address, request_id=request_id
    )
    return PasswordResetResponse(
        message=(
            "If an account exists for that address, a reset link is on its way. "
            "The link expires and can only be used once."
        ),
        dev_reset_token=token if _dev_email_token(settings) else None,
    )


@router.post(
    "/password/reset/confirm",
    response_model=MessageResponse,
    summary="Reset a password with a token",
    description=(
        "Redeems a reset token. Every session for the account is revoked, including "
        "the caller's: a reset arrives by email, so whoever clicked the link is not "
        "necessarily whoever holds an open session. An invented, expired or already "
        "used token all produce the same error."
    ),
)
async def confirm_password_reset(
    payload: PasswordResetConfirmRequest,
    response: Response,
    service: PasswordServiceDep,
    settings: SettingsDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """Set a new password using a reset token."""
    await service.complete_password_reset(
        token=payload.token,
        new_password=payload.new_password,
        ip_address=ip_address,
        request_id=request_id,
    )
    _clear_session_cookies(response, settings)
    return MessageResponse(
        message="Password reset. Every session has been signed out; please sign in again."
    )


@router.post(
    "/email/verify",
    response_model=MessageResponse,
    summary="Confirm an email address",
    description="Redeems a verification token and activates an account that was pending.",
)
async def verify_email(
    payload: VerifyEmailRequest,
    service: PasswordServiceDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """Confirm ownership of the address."""
    await service.confirm_email(token=payload.token, ip_address=ip_address, request_id=request_id)
    return MessageResponse(message="Email address confirmed. You can sign in now.")


@router.post(
    "/email/verify/request",
    response_model=MessageResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Resend the confirmation email",
    description=(
        "Unauthenticated by necessity: an account whose address is unconfirmed cannot "
        "sign in, so it cannot be authenticated while asking for the email again. The "
        "response is the same whether or not the address exists."
    ),
)
async def resend_verification(
    payload: ResendVerificationRequest,
    service: PasswordServiceDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """Issue a fresh verification token."""
    await service.resend_email_verification(
        email=payload.email, ip_address=ip_address, request_id=request_id
    )
    return MessageResponse(
        message="If that address is registered and unconfirmed, a new link is on its way."
    )


# ---------------------------------------------------------------------------
# Second factor
# ---------------------------------------------------------------------------
@router.post(
    "/mfa/enroll",
    response_model=MfaEnrollmentResponse,
    summary="Begin second-factor enrollment",
    description=(
        "Generates a shared secret and a set of single-use recovery codes. The account "
        "is **not** protected until `/auth/mfa/confirm` accepts a code, so a user who "
        "scans the QR code incorrectly is not locked out of an account that never had "
        "a working second factor. The secret and the codes are returned once and "
        "cannot be retrieved again: the secret is stored encrypted and each code is "
        "stored as a digest."
    ),
)
async def enroll_mfa(
    auth: CurrentAuthDep,
    service: MfaServiceDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MfaEnrollmentResponse:
    """Start enrolling an authenticator app."""
    enrollment = await service.begin_enrollment(
        user=auth.user, ip_address=ip_address, request_id=request_id
    )
    return MfaEnrollmentResponse(
        secret=enrollment.secret,
        provisioning_uri=enrollment.provisioning_uri,
        recovery_codes=enrollment.recovery_codes,
        message=(
            "Scan the QR code with your authenticator app, then confirm with a code "
            "from it. Store the recovery codes somewhere offline: each one works once, "
            "and they cannot be shown again."
        ),
    )


@router.post(
    "/mfa/confirm",
    response_model=MessageResponse,
    summary="Confirm second-factor enrollment",
    description=(
        "Accepts a code from the enrolled authenticator and switches the second factor "
        "on. The code that confirms enrollment is itself spent, so it cannot be "
        "replayed as the first sign-in with the new factor."
    ),
)
async def confirm_mfa(
    payload: MfaConfirmRequest,
    auth: CurrentAuthDep,
    service: MfaServiceDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """Prove possession of the authenticator."""
    await service.confirm_enrollment(
        user=auth.user, code=payload.code, ip_address=ip_address, request_id=request_id
    )
    return MessageResponse(message="Two-factor authentication is now enabled.")


@router.post(
    "/mfa/cancel",
    response_model=MessageResponse,
    summary="Abandon a pending enrollment",
    description=(
        "Discards a secret that was generated but never confirmed, along with the "
        "recovery codes issued with it."
    ),
)
async def cancel_mfa(
    auth: CurrentAuthDep,
    service: MfaServiceDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """Cancel an enrollment that was never confirmed."""
    await service.cancel_enrollment(user=auth.user, ip_address=ip_address, request_id=request_id)
    return MessageResponse(message="Pending enrollment cancelled.")


@router.post(
    "/mfa/disable",
    response_model=MessageResponse,
    summary="Remove the second factor",
    description=(
        "Requires the password, not just a session: removing MFA from an open session "
        "on an unlocked machine would let anybody at that machine take the second "
        "factor off the account permanently. Recovery codes are destroyed with it."
    ),
)
async def disable_mfa(
    payload: MfaDisableRequest,
    auth: CurrentAuthDep,
    mfa: MfaServiceDep,
    passwords: PasswordServiceDep,
    ip_address: ClientIpDep,
    request_id: RequestIdDep,
) -> MessageResponse:
    """Turn off two-factor authentication."""
    if not passwords.verify_current_password(user=auth.user, password=payload.password):
        # Audited in a transaction of its own: the refusal rolls this request back, and
        # a failed attempt to remove a second factor is exactly the kind of event that
        # has to survive the rollback it causes (§52, §62).
        await passwords.audit_reauthorisation_failure(
            user=auth.user,
            action="AUTH_MFA_DISABLE_REJECTED",
            reason="the password did not verify when disabling the second factor",
            ip_address=ip_address,
            request_id=request_id,
        )
        raise InvalidCredentialsError
    removed = await mfa.disable(user=auth.user, ip_address=ip_address, request_id=request_id)
    return MessageResponse(
        message=(f"Two-factor authentication is off. {removed} recovery code(s) were destroyed.")
    )


@router.get(
    "/mfa",
    response_model=MfaStatusResponse,
    summary="Second-factor status",
    description=(
        "Whether a second factor is enabled and how many recovery codes are left. "
        "Never the codes themselves, and never the secret: the count is there so a "
        "user who has spent most of them knows to re-enroll before they run out."
    ),
)
async def mfa_status(auth: CurrentAuthDep, service: MfaServiceDep) -> MfaStatusResponse:
    """Report the state of the caller's second factor."""
    remaining = await service.remaining_recovery_codes(auth.user)
    return MfaStatusResponse(
        enabled=auth.user.mfa_confirmed,
        confirmed_at=auth.user.totp_confirmed_at,
        recovery_codes_remaining=remaining,
    )
