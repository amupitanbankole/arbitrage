"""Roles and granular permissions (§41, §43, §102).

Seven roles. Four are platform staff — :attr:`Role.OWNER`, :attr:`Role.ADMIN`,
:attr:`Role.COMPLIANCE_OFFICER`, :attr:`Role.SUPPORT_AGENT` and
:attr:`Role.RISK_MANAGER` — and two are customer roles, :attr:`Role.TRADER` and
:attr:`Role.VIEWER`, where ``VIEWER`` is a read-only account such as an accountant
or a business partner given visibility without control.

Grants live in code, deliberately.

The alternative — a ``role_permissions`` table an administrator can edit — was
considered and rejected for this phase. A grant that nobody reviewed is the most
dangerous kind: it is invisible in a diff, invisible in code review, and it takes
effect the moment it is written. Keeping the mapping here means every privilege
change is a reviewed, versioned, deployable change with an author and a date, which
is what §44's audit requirement is really after. The catalogue is still *data* (a
mapping, not ``if role == "admin"`` scattered through the code), so moving it into
the database later — behind the audited admin UI that Phase 9 delivers — is a
migration rather than a rewrite.

Two rules are enforced by tests rather than by hope, because both are the kind of
invariant that erodes one innocent-looking grant at a time:

* **No customer role holds an ``:any`` permission.** ``TRADER`` and ``VIEWER`` may
  only ever reach their own resources. A single ``user:read:any`` added to ``TRADER``
  to "make the support page work" would be a full cross-tenant data leak.
* **Every role holds the self-service set.** A ``VIEWER`` who cannot sign out of
  their own session or change their own password is a ``VIEWER`` who has to ask an
  administrator for basic account hygiene, which is how support tickets become
  privilege escalations.

Permission strings follow ``resource:action[:scope]``. The scope is ``self`` (the
caller's own object), ``any`` (across accounts) or ``internal`` (platform internals
— configuration, metrics, health detail — which is neither of the other two). An
unscoped permission such as ``audit:read`` is inherently platform-wide, so it is
only ever held by staff roles; that is asserted by a test rather than left to
review. Enforcement is always server-side: a hidden button in the UI is not a
control (§43).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

__all__ = [
    "OWNER_ONLY_PERMISSIONS",
    "PUBLIC_PERMISSIONS",
    "SELF_SERVICE_PERMISSIONS",
    "STAFF_ROLES",
    "Permission",
    "Role",
    "default_role",
    "is_staff",
    "permissions_for",
    "role_descriptions",
    "role_has_permission",
]


class Role(StrEnum):
    """The seven platform roles (§41).

    Stored as ``VARCHAR`` with a ``CHECK`` constraint rather than a native
    PostgreSQL enum, for the reasons in :mod:`arb_persistence.models.enums`:
    adding a native enum value cannot be rolled back inside a migration.
    """

    #: Everything, including the two acts nobody else may perform.
    OWNER = "OWNER"
    #: Full administration, short of ownership transfer and audit archival.
    ADMIN = "ADMIN"
    #: Read-only across the platform, plus the audit trail. Investigates, never acts.
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"
    #: Resolves user problems: read accounts and sessions, end sessions, reset a
    #: password. No trading, no risk controls, no exchange credentials, no grants.
    SUPPORT_AGENT = "SUPPORT_AGENT"
    #: Controls risk: limits, circuit breakers, the kill switch. Can stop anything,
    #: and cannot start live trading.
    RISK_MANAGER = "RISK_MANAGER"
    #: An ordinary customer. Own resources only, and trading subject to the gates
    #: in §31 (feature flag, per-bot activation, risk engine).
    TRADER = "TRADER"
    #: A read-only customer account.
    VIEWER = "VIEWER"


class Permission(StrEnum):
    """The granular permission catalogue (§43).

    Declaring the whole catalogue now — including permissions whose enforcement
    arrives with a later phase — is what makes a grant reviewable: a reviewer can
    see that ``SUPPORT_AGENT`` lacks ``exchange:read:any`` rather than discovering
    it in Phase 3 when the endpoint appears. Permissions marked *(later phase)*
    are not wired to any route yet; nothing grants access to a resource that does
    not exist.
    """

    # S105 (hardcoded password) fires on the two members below because their
    # identifier contains "password" and their value is a literal. Both are
    # permission *names* — a string compared against a grant set — not a
    # credential. Suppressed per line rather than for the module.
    # --- Account self-service (Phase 2) ---
    ACCOUNT_READ_SELF = "account:read:self"
    ACCOUNT_UPDATE_SELF = "account:update:self"
    ACCOUNT_DELETE_SELF = "account:delete:self"
    PASSWORD_CHANGE_SELF = "password:change:self"  # noqa: S105
    MFA_MANAGE_SELF = "mfa:manage:self"
    SESSION_READ_SELF = "session:read:self"
    SESSION_REVOKE_SELF = "session:revoke:self"

    # --- Administration of other accounts (Phase 2 declares, Phase 9 surfaces) ---
    USER_CREATE = "user:create"
    USER_READ_ANY = "user:read:any"
    USER_UPDATE_ANY = "user:update:any"
    USER_SUSPEND = "user:suspend"
    USER_DELETE_ANY = "user:delete:any"
    SESSION_READ_ANY = "session:read:any"
    SESSION_REVOKE_ANY = "session:revoke:any"
    PASSWORD_RESET_ANY = "password:reset:any"  # noqa: S105
    ROLE_READ = "role:read"
    ROLE_ASSIGN = "role:assign"

    # --- Oversight (Phase 2 declares, Phase 9 surfaces) ---
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    #: Owner-only. The audit log is append-only (§53, §83); archival is a
    #: documented, deliberate act by the person accountable for the platform.
    AUDIT_ARCHIVE = "audit:archive"
    SECURITY_READ = "security:read"
    SECURITY_RESPOND = "security:respond"
    SYSTEM_READ_INTERNAL = "system:read:internal"
    METRICS_READ = "metrics:read"
    FEATURE_FLAG_READ = "feature_flag:read"
    FEATURE_FLAG_UPDATE = "feature_flag:update"
    #: Owner-only: transferring accountability for the platform.
    PLATFORM_TRANSFER_OWNERSHIP = "platform:transfer_ownership"

    # --- Public read ---
    SYSTEM_READ = "system:read"

    # --- Exchange connectivity (Phase 3) ---
    #: The ``read`` grants cover credential *records* — which exchange, the label,
    #: the permissions requested, when it was connected — and never the secret
    #: itself. An API secret is write-only by construction (§56): no role reads it
    #: back, including ``OWNER``, so ``exchange:read:any`` is not a way for staff
    #: to obtain a customer's key. The encrypted blob is only ever decrypted
    #: inside the exchange adapter, per request.
    EXCHANGE_CONNECT_SELF = "exchange:connect:self"
    EXCHANGE_READ_SELF = "exchange:read:self"
    EXCHANGE_DISCONNECT_SELF = "exchange:disconnect:self"
    EXCHANGE_READ_ANY = "exchange:read:any"

    # --- Market data and opportunities (Phase 4, Phase 5) ---
    MARKET_READ = "market:read"
    OPPORTUNITY_READ_SELF = "opportunity:read:self"

    # --- Risk (Phase 6) ---
    RISK_READ_SELF = "risk:read:self"
    RISK_UPDATE_SELF = "risk:update:self"
    RISK_READ_ANY = "risk:read:any"
    RISK_UPDATE_ANY = "risk:update:any"
    #: The global kill switch (§26). Stopping everything is the one act a risk
    #: officer must never have to ask permission for.
    KILL_SWITCH_ACTIVATE = "kill_switch:activate"

    # --- Trading (Phase 7, Phase 11) ---
    BOT_READ_SELF = "bot:read:self"
    BOT_MANAGE_SELF = "bot:manage:self"
    BOT_READ_ANY = "bot:read:any"
    BOT_MANAGE_ANY = "bot:manage:any"
    TRADE_READ_SELF = "trade:read:self"
    TRADE_EXECUTE_SELF = "trade:execute:self"
    TRADE_READ_ANY = "trade:read:any"
    #: Activating live trading for one's own bot (§31). Always paired at runtime
    #: with the environment master switch and the ``live_trading`` feature flag;
    #: a permission is one of three gates, never the only one.
    LIVE_TRADING_ACTIVATE_SELF = "live_trading:activate:self"
    LIVE_TRADING_ACTIVATE_ANY = "live_trading:activate:any"

    # --- Portfolio, backtesting, rebalancing, notifications (Phases 8-12) ---
    PORTFOLIO_READ_SELF = "portfolio:read:self"
    BACKTEST_RUN_SELF = "backtest:run:self"
    BACKTEST_READ_SELF = "backtest:read:self"
    REBALANCE_READ_SELF = "rebalance:read:self"
    NOTIFICATION_MANAGE_SELF = "notification:manage:self"


#: Permissions only the owner holds. Kept explicit so ``ADMIN`` is defined by
#: subtraction and a new owner-only act cannot leak into it by accident.
OWNER_ONLY_PERMISSIONS: Final[frozenset[Permission]] = frozenset(
    {
        Permission.PLATFORM_TRANSFER_OWNERSHIP,
        Permission.AUDIT_ARCHIVE,
    }
)

#: What every authenticated person can do to their own account, whatever their
#: role. Enforced as a subset of every grant set by a test.
SELF_SERVICE_PERMISSIONS: Final[frozenset[Permission]] = frozenset(
    {
        Permission.ACCOUNT_READ_SELF,
        Permission.ACCOUNT_UPDATE_SELF,
        Permission.PASSWORD_CHANGE_SELF,
        Permission.MFA_MANAGE_SELF,
        Permission.SESSION_READ_SELF,
        Permission.SESSION_REVOKE_SELF,
        Permission.SYSTEM_READ,
    }
)

#: Unscoped permissions that carry no authority over anybody else's data.
#:
#: Most unscoped permissions — ``audit:read``, ``user:create``, ``role:read`` — are
#: inherently platform-wide, which is why they are staff-only. These two are the
#: exception: market data and public system status belong to nobody, and are served
#: on endpoints that do not even require authentication. Naming them explicitly is
#: what lets a test assert "no customer role holds an unscoped permission outside
#: this set" instead of maintaining a list of every administrative permission
#: anywhere in the catalogue.
PUBLIC_PERMISSIONS: Final[frozenset[Permission]] = frozenset(
    {
        Permission.MARKET_READ,
        Permission.SYSTEM_READ,
    }
)

#: Roles that act for the platform rather than for themselves.
STAFF_ROLES: Final[frozenset[Role]] = frozenset(
    {
        Role.OWNER,
        Role.ADMIN,
        Role.COMPLIANCE_OFFICER,
        Role.SUPPORT_AGENT,
        Role.RISK_MANAGER,
    }
)

#: Read-only oversight: everything a compliance officer needs, nothing they could
#: change. Deliberately excludes exchange credentials and trading — an auditor who
#: can also move money is not an auditor (§41, §44).
_COMPLIANCE_GRANTS: Final[frozenset[Permission]] = frozenset(
    {
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.SECURITY_READ,
        Permission.USER_READ_ANY,
        Permission.SESSION_READ_ANY,
        Permission.EXCHANGE_READ_ANY,
        Permission.TRADE_READ_ANY,
        Permission.BOT_READ_ANY,
        Permission.RISK_READ_ANY,
        Permission.SYSTEM_READ_INTERNAL,
        Permission.METRICS_READ,
        Permission.FEATURE_FLAG_READ,
        Permission.ROLE_READ,
        Permission.MARKET_READ,
    }
)

#: Customer-facing support: enough to diagnose and to end a compromised session,
#: not enough to trade, change risk limits, read exchange credentials or grant
#: roles. Resetting a password is the one write, and it is audited (§44).
_SUPPORT_GRANTS: Final[frozenset[Permission]] = frozenset(
    {
        Permission.USER_READ_ANY,
        Permission.SESSION_READ_ANY,
        Permission.SESSION_REVOKE_ANY,
        Permission.PASSWORD_RESET_ANY,
        Permission.AUDIT_READ,
        Permission.SECURITY_READ,
        Permission.SYSTEM_READ_INTERNAL,
        Permission.ROLE_READ,
    }
)

#: Risk control. Note what is absent: ``LIVE_TRADING_ACTIVATE_ANY`` and
#: ``TRADE_EXECUTE_SELF``. A risk manager can stop anything and start nothing.
_RISK_GRANTS: Final[frozenset[Permission]] = frozenset(
    {
        Permission.RISK_READ_ANY,
        Permission.RISK_UPDATE_ANY,
        Permission.KILL_SWITCH_ACTIVATE,
        Permission.TRADE_READ_ANY,
        Permission.BOT_READ_ANY,
        Permission.BOT_MANAGE_ANY,
        Permission.SECURITY_READ,
        Permission.SECURITY_RESPOND,
        Permission.AUDIT_READ,
        Permission.SYSTEM_READ_INTERNAL,
        Permission.METRICS_READ,
        Permission.FEATURE_FLAG_READ,
        Permission.MARKET_READ,
        Permission.OPPORTUNITY_READ_SELF,
    }
)

#: What a customer can do with their own account and their own trading.
_TRADER_GRANTS: Final[frozenset[Permission]] = frozenset(
    {
        Permission.ACCOUNT_DELETE_SELF,
        Permission.EXCHANGE_CONNECT_SELF,
        Permission.EXCHANGE_READ_SELF,
        Permission.EXCHANGE_DISCONNECT_SELF,
        Permission.MARKET_READ,
        Permission.OPPORTUNITY_READ_SELF,
        Permission.RISK_READ_SELF,
        Permission.RISK_UPDATE_SELF,
        Permission.BOT_READ_SELF,
        Permission.BOT_MANAGE_SELF,
        Permission.TRADE_READ_SELF,
        Permission.TRADE_EXECUTE_SELF,
        Permission.LIVE_TRADING_ACTIVATE_SELF,
        Permission.PORTFOLIO_READ_SELF,
        Permission.BACKTEST_RUN_SELF,
        Permission.BACKTEST_READ_SELF,
        Permission.REBALANCE_READ_SELF,
        Permission.NOTIFICATION_MANAGE_SELF,
    }
)

#: Read-only customer account: the same visibility as a trader, no mutation.
#: ``ACCOUNT_UPDATE_SELF``, ``PASSWORD_CHANGE_SELF`` and the session permissions
#: arrive through :data:`SELF_SERVICE_PERMISSIONS` — being read-only must not mean
#: being unable to secure your own account.
_VIEWER_GRANTS: Final[frozenset[Permission]] = frozenset(
    {
        # Closing your own account is not a mutation of the platform's business
        # data, and refusing it would force a read-only user to open a support
        # ticket to exercise a right they have over their own account.
        Permission.ACCOUNT_DELETE_SELF,
        Permission.EXCHANGE_READ_SELF,
        Permission.MARKET_READ,
        Permission.OPPORTUNITY_READ_SELF,
        Permission.RISK_READ_SELF,
        Permission.BOT_READ_SELF,
        Permission.TRADE_READ_SELF,
        Permission.PORTFOLIO_READ_SELF,
        Permission.BACKTEST_READ_SELF,
        Permission.REBALANCE_READ_SELF,
    }
)

#: The mapping. ``OWNER`` is every permission; ``ADMIN`` is every permission the
#: owner does not keep to themselves.
ROLE_PERMISSIONS: Final[dict[Role, frozenset[Permission]]] = {
    Role.OWNER: frozenset(Permission),
    Role.ADMIN: frozenset(Permission) - OWNER_ONLY_PERMISSIONS,
    Role.COMPLIANCE_OFFICER: _COMPLIANCE_GRANTS | SELF_SERVICE_PERMISSIONS,
    Role.SUPPORT_AGENT: _SUPPORT_GRANTS | SELF_SERVICE_PERMISSIONS,
    Role.RISK_MANAGER: _RISK_GRANTS | SELF_SERVICE_PERMISSIONS,
    Role.TRADER: _TRADER_GRANTS | SELF_SERVICE_PERMISSIONS,
    Role.VIEWER: _VIEWER_GRANTS | SELF_SERVICE_PERMISSIONS,
}

_ROLE_DESCRIPTIONS: Final[dict[Role, str]] = {
    Role.OWNER: "Full control of the platform, including ownership transfer and audit archival.",
    Role.ADMIN: "Full administration except the two acts reserved to the owner.",
    Role.COMPLIANCE_OFFICER: "Read-only oversight across the platform, plus the audit trail.",
    Role.SUPPORT_AGENT: "Diagnose user problems, end sessions and reset passwords. No trading.",
    Role.RISK_MANAGER: "Risk limits, circuit breakers and the kill switch. Can stop, cannot start.",
    Role.TRADER: "A customer: own account, own exchange connections, own bots and trades.",
    Role.VIEWER: "A read-only customer account.",
}


def permissions_for(role: Role | str) -> frozenset[Permission]:
    """Return the permissions a role holds.

    An unrecognised role yields nothing rather than raising: authorization asks
    "may this caller do this?", and for an unknown role the only safe answer is no.
    Raising would turn a data problem into a 500 on every request that account
    makes (§43).
    """
    try:
        resolved = Role(role)
    except ValueError:
        return frozenset()
    return ROLE_PERMISSIONS[resolved]


def role_has_permission(role: Role | str, permission: Permission | str) -> bool:
    """Return whether ``role`` grants ``permission``.

    An unrecognised permission is never granted, for the same reason as an
    unrecognised role: fail closed.
    """
    try:
        resolved = Permission(permission)
    except ValueError:
        return False
    return resolved in permissions_for(role)


def is_staff(role: Role | str) -> bool:
    """Return whether the role acts for the platform rather than for itself."""
    try:
        return Role(role) in STAFF_ROLES
    except ValueError:
        return False


def default_role() -> Role:
    """The role a self-registered account receives (§41).

    ``TRADER``, never a staff role: nothing about signing up may confer platform
    authority, and the first owner is created by an operator through the
    management command rather than by registering.
    """
    return Role.TRADER


def role_descriptions() -> dict[str, str]:
    """Every role and what it is for, as a JSON-safe mapping (§68).

    Published by the API so an administrator assigning a role sees the same
    description a reviewer reading this module sees.
    """
    return {role.value: description for role, description in _ROLE_DESCRIPTIONS.items()}
