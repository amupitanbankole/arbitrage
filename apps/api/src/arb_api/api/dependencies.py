"""Route-level dependencies wiring services to requests (§115).

Kept separate from :mod:`arb_api.state` because services import ``AppState``;
resolving them here rather than there avoids a circular import between the state
container and the service layer.

Dependencies construct a service per request. Services are stateless wrappers around
a session and the shared container, so this costs an object allocation and nothing
else — while making lifetime and transaction scope explicit at the call site.

Authentication lives here rather than in middleware for one reason: a middleware
cannot make an endpoint's *requirement* visible. ``CurrentAuthDep`` in a signature is
a declaration that FastAPI puts in the OpenAPI document, that a reviewer sees when
reading the route, and that a test can override with ``app.dependency_overrides``.
Middleware-enforced authentication is none of those things, and the failure mode is
an endpoint somebody forgot to list in an exclusion table (§43, §102).

Every authenticated dependency resolves through :data:`UnitOfWorkDep`, not the
read-only session. Two reasons: validating a request writes ``last_seen_at``, which
is what makes the idle timeout mean anything, and an authorization decision must be
made against the same transaction snapshot as any write the endpoint goes on to
perform — otherwise a role change committed between the two reads can produce a
request that was authorized as an administrator and executed as a customer.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Annotated, Final

from fastapi import Depends, Request

from arb_api.services.audit_service import AuditActor, AuditService
from arb_api.services.auth_results import AuthenticatedRequest
from arb_api.services.auth_service import AuthService
from arb_api.services.feature_flag_service import FeatureFlagService
from arb_api.services.health_service import HealthService
from arb_api.services.mfa_service import MfaService
from arb_api.services.password_service import PasswordService
from arb_api.services.session_service import SessionService
from arb_api.services.system_service import SystemService
from arb_api.state import SessionDep, StateDep, UnitOfWorkDep, get_settings_dep
from arb_core.config import Settings
from arb_core.context import request_id as current_request_id
from arb_core.errors import AuthenticationError, PermissionDeniedError
from arb_core.security.ratelimit import RateLimiter
from arb_core.security.rbac import permissions_for
from arb_persistence.models.auth import User
from arb_persistence.models.enums import ActorType, AuditResult

if TYPE_CHECKING:
    from arb_core.security.rbac import Permission

__all__ = [
    "AuditDep",
    "AuthServiceDep",
    "ClientIpDep",
    "CurrentAuthDep",
    "CurrentUserDep",
    "FeatureFlagDep",
    "HealthServiceDep",
    "MfaServiceDep",
    "PasswordServiceDep",
    "RateLimiterDep",
    "RequestIdDep",
    "SessionServiceDep",
    "SettingsDep",
    "SystemServiceDep",
    "UserAgentDep",
    "get_audit_service",
    "get_auth_service",
    "get_client_ip",
    "get_current_auth",
    "get_current_user",
    "get_feature_flag_service",
    "get_health_service",
    "get_mfa_service",
    "get_password_service",
    "get_rate_limiter",
    "get_request_id",
    "get_session_service",
    "get_system_service",
    "get_user_agent",
    "require_permission",
]

#: The ``Authorization`` scheme this API accepts. Compared case-insensitively, as
#: RFC 7235 requires, because a client that sends ``bearer`` is not wrong.
_BEARER_SCHEME: Final[str] = "bearer"

#: Column width of ``user_sessions.user_agent``. A longer header is truncated rather
#: than rejected: refusing a request because a browser was verbose would be a denial
#: of service with nobody to blame, and the value is only ever displayed.
_USER_AGENT_WIDTH: Final[int] = 512

#: ``X-Forwarded-For`` is a list, newest proxy last. The first entry is the client.
_FORWARDED_FOR_HEADER: Final[str] = "x-forwarded-for"


# ---------------------------------------------------------------------------
# Existing services (Phase 1)
# ---------------------------------------------------------------------------
def get_health_service(state: StateDep) -> HealthService:
    """Resolve the health aggregation service."""
    return HealthService(state)


def get_feature_flag_service(state: StateDep, session: SessionDep) -> FeatureFlagService:
    """Resolve feature-flag evaluation backed by the database and Redis cache."""
    return FeatureFlagService(settings=state.settings, session=session, redis=state.redis)


def get_system_service(
    state: StateDep,
    flags: Annotated[FeatureFlagService, Depends(get_feature_flag_service)],
) -> SystemService:
    """Resolve the system status service."""
    return SystemService(state, flags)


#: Configuration, for the handful of routes that have to know how to set a cookie
#: or whether email delivery exists in this deployment.
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]

HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]
FeatureFlagDep = Annotated[FeatureFlagService, Depends(get_feature_flag_service)]
SystemServiceDep = Annotated[SystemService, Depends(get_system_service)]


# ---------------------------------------------------------------------------
# Request attribution
# ---------------------------------------------------------------------------
def get_client_ip(request: Request, state: StateDep) -> str | None:
    """The address this request is attributed to, for limits and audit entries.

    ``X-Forwarded-For`` is believed only when ``TRUST_PROXY_HEADERS`` is on *and* the
    direct peer is listed in ``FORWARDED_ALLOW_IPS``. Believing the header
    unconditionally would hand every caller control of their own identity: one
    ``X-Forwarded-For: <fresh address>`` per request is an unlimited rate-limit budget
    and an audit trail that names nobody. Ignoring it entirely would attribute every
    request behind a reverse proxy to the proxy, which is the same loss by other
    means — so the answer is to trust it exactly as far as the deployment says to.
    """
    peer = request.client.host if request.client is not None else None
    settings: Settings = state.settings
    if not settings.trust_proxy_headers:
        return peer

    forwarded = request.headers.get(_FORWARDED_FOR_HEADER)
    if not forwarded:
        return peer

    allowed = {entry.strip() for entry in settings.forwarded_allow_ips.split(",") if entry.strip()}
    if "*" not in allowed and peer not in allowed:
        # The peer is not a proxy we were told about, so anything it forwards is a
        # claim rather than a fact.
        return peer

    first = forwarded.split(",")[0].strip()
    return first or peer


def get_user_agent(request: Request) -> str | None:
    """The client's self-description, truncated to the column width."""
    value = request.headers.get("user-agent")
    if not value:
        return None
    return value[:_USER_AGENT_WIDTH]


def get_request_id() -> str | None:
    """The correlation id the request-context middleware bound for this request."""
    return current_request_id()


ClientIpDep = Annotated[str | None, Depends(get_client_ip)]
UserAgentDep = Annotated[str | None, Depends(get_user_agent)]
RequestIdDep = Annotated[str | None, Depends(get_request_id)]


# ---------------------------------------------------------------------------
# Authentication services
# ---------------------------------------------------------------------------
def get_rate_limiter(state: StateDep) -> RateLimiter:
    """Resolve the rate limiter over the shared Redis handle."""
    return RateLimiter.from_settings(state.settings, state.redis)


def get_audit_service(state: StateDep, uow: UnitOfWorkDep) -> AuditService:
    """Resolve the audit writer.

    Given the :class:`~arb_core.db.session.Database` as well as the session so that a
    *rejection* can be written in a transaction of its own. A refusal raises, this
    request's transaction rolls back, and an entry written into it would disappear
    along with the event it describes — which is how a platform ends up with an audit
    log full of successes and no record of anything anybody tried (§53, §62).
    """
    return AuditService(uow, database=state.database)


def get_session_service(
    state: StateDep,
    uow: UnitOfWorkDep,
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> SessionService:
    """Resolve session issuance, rotation and validation."""
    return SessionService(
        session=uow, settings=state.settings, rate_limiter=limiter, database=state.database
    )


def get_mfa_service(
    state: StateDep,
    uow: UnitOfWorkDep,
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> MfaService:
    """Resolve second-factor enrollment and verification."""
    return MfaService(
        session=uow, settings=state.settings, rate_limiter=limiter, database=state.database
    )


def get_password_service(
    state: StateDep,
    uow: UnitOfWorkDep,
    sessions: Annotated[SessionService, Depends(get_session_service)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> PasswordService:
    """Resolve password changes and the emailed-token flows."""
    return PasswordService(
        session=uow,
        settings=state.settings,
        sessions=sessions,
        rate_limiter=limiter,
        database=state.database,
    )


def get_auth_service(
    state: StateDep,
    uow: UnitOfWorkDep,
    sessions: Annotated[SessionService, Depends(get_session_service)],
    mfa: Annotated[MfaService, Depends(get_mfa_service)],
    passwords: Annotated[PasswordService, Depends(get_password_service)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> AuthService:
    """Resolve registration and sign-in."""
    return AuthService(
        session=uow,
        settings=state.settings,
        sessions=sessions,
        mfa=mfa,
        passwords=passwords,
        rate_limiter=limiter,
        database=state.database,
    )


RateLimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
AuditDep = Annotated[AuditService, Depends(get_audit_service)]
SessionServiceDep = Annotated[SessionService, Depends(get_session_service)]
MfaServiceDep = Annotated[MfaService, Depends(get_mfa_service)]
PasswordServiceDep = Annotated[PasswordService, Depends(get_password_service)]
AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


# ---------------------------------------------------------------------------
# The authenticated caller
# ---------------------------------------------------------------------------
async def get_current_auth(
    request: Request,
    sessions: SessionServiceDep,
    ip_address: ClientIpDep,
    user_agent: UserAgentDep,
    request_id: RequestIdDep,
) -> AuthenticatedRequest:
    """Require a bearer token that the session and account behind it still honour.

    A missing, malformed or expired token is one :class:`AuthenticationError` with a
    ``WWW-Authenticate`` header. The distinctions an attacker would care about —
    unknown token, revoked session, disabled account, session older than the last
    password change — are audited and not reported (§71).
    """
    header = request.headers.get("authorization")
    if not header:
        raise AuthenticationError
    scheme, _, credential = header.partition(" ")
    if scheme.strip().lower() != _BEARER_SCHEME or not credential.strip():
        # Naming the scheme in the header tells the client what to send instead, and
        # discloses nothing about the credential it did send.
        raise AuthenticationError(www_authenticate='Bearer error="invalid_request"')

    return await sessions.authenticate(
        access_token=credential.strip(),
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
    )


def get_current_user(auth: CurrentAuthDep) -> User:
    """The authenticated account, for endpoints that do not need the session."""
    return auth.user


CurrentAuthDep = Annotated[AuthenticatedRequest, Depends(get_current_auth)]
CurrentUserDep = Annotated[User, Depends(get_current_user)]


def require_permission(
    permission: Permission,
) -> Callable[..., Awaitable[AuthenticatedRequest]]:
    """Build a dependency that enforces one permission, server-side.

    The check reads the caller's *current* role from the database row rather than a
    claim in the token, so demoting somebody takes effect on their next request
    instead of when their access token next expires. Denials are audited as
    ``DENIED`` and not merely as failures: a run of denials against an administrative
    permission from an ordinary account is privilege-escalation probing, and it is
    only visible if the refusal is recorded (§43, §52, §130).
    """

    async def dependency(
        request: Request,
        auth: CurrentAuthDep,
        audit: AuditDep,
        ip_address: ClientIpDep,
        user_agent: UserAgentDep,
        request_id: RequestIdDep,
    ) -> AuthenticatedRequest:
        if permission in permissions_for(auth.user.role):
            return auth

        await audit.record_failure(
            action="AUTH_PERMISSION_DENIED",
            resource_type="user",
            resource_id=auth.user.id,
            actor=AuditActor(
                actor_type=ActorType.USER,
                actor_id=auth.user.id,
                role=auth.user.role.value,
                ip_address=ip_address,
                user_agent=user_agent,
            ),
            new_value={
                "required_permission": permission.value,
                "role": auth.user.role.value,
                "path": request.scope["path"],
                "method": request.method,
            },
            reason="the caller's role does not grant the required permission",
            result=AuditResult.DENIED,
            request_id=request_id,
        )
        # The required permission is safe to disclose: the caller is authenticated,
        # and knowing what they lack is how a legitimate user finds out which
        # administrator to ask. What is not disclosed is whether anybody else has it.
        raise PermissionDeniedError(details={"required_permission": permission.value})

    # FastAPI injects `request` from the call and leaves it out of the generated
    # OpenAPI document, so the dependency's parameters stay exactly the permissions
    # and attribution it needs.
    return dependency
