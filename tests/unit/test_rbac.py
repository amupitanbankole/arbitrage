"""Roles, permissions, and the invariants that keep the mapping honest (§41, §43, §102).

A permission catalogue fails in a particular way: one grant is added to make a
screen work, nobody notices that it is an ``:any`` grant on a customer role, and
every customer can now read every other customer's data. Nothing crashes. So the
tests here are mostly *policy invariants* rather than lookup assertions — they are
what makes the next careless grant fail a build instead of shipping.
"""

from __future__ import annotations

import re

import pytest

from arb_core.security.rbac import (
    OWNER_ONLY_PERMISSIONS,
    PUBLIC_PERMISSIONS,
    SELF_SERVICE_PERMISSIONS,
    STAFF_ROLES,
    Permission,
    Role,
    default_role,
    is_staff,
    permissions_for,
    role_descriptions,
    role_has_permission,
)

CUSTOMER_ROLES = (Role.TRADER, Role.VIEWER)
ALL_ROLES = tuple(Role)

#: ``resource:action`` or ``resource:action:scope``, where scope is one of:
#: ``self`` (the caller's own object), ``any`` (across accounts) or ``internal``
#: (platform internals, which is neither — it is not another user's data).
#: Enforced as a structural rule so a typo like ``trade_execute:self`` cannot enter
#: the catalogue unnoticed, and so a *new* scope has to be added here deliberately
#: rather than appearing in one grant and silently escaping the ``:any`` checks.
_PERMISSION_SHAPE = re.compile(r"^[a-z][a-z_]*:[a-z][a-z_]*(?::(?:self|any|internal))?$")


class TestCatalogue:
    def test_there_are_exactly_seven_roles(self) -> None:
        assert len(Role) == 7
        assert {role.value for role in Role} == {
            "OWNER",
            "ADMIN",
            "COMPLIANCE_OFFICER",
            "SUPPORT_AGENT",
            "RISK_MANAGER",
            "TRADER",
            "VIEWER",
        }

    def test_every_role_has_a_grant_set(self) -> None:
        for role in ALL_ROLES:
            assert permissions_for(role), f"{role} has no permissions"

    def test_every_role_is_described(self) -> None:
        descriptions = role_descriptions()
        assert set(descriptions) == {role.value for role in Role}
        assert all(description.strip() for description in descriptions.values())

    def test_descriptions_are_json_safe(self) -> None:
        """Published over the API, so they must serialise without help (§68)."""
        import json

        assert json.loads(json.dumps(role_descriptions())) == role_descriptions()

    def test_permission_strings_are_well_formed(self) -> None:
        for permission in Permission:
            assert _PERMISSION_SHAPE.match(permission.value), permission.value

    def test_permission_values_are_unique(self) -> None:
        values = [permission.value for permission in Permission]
        assert len(set(values)) == len(values)

    def test_role_values_match_their_names_for_database_storage(self) -> None:
        """Stored as ``VARCHAR`` + ``CHECK``, so the value is the contract."""
        for role in Role:
            assert role.value == role.name
            assert Role(role.value) is role

    def test_permissions_are_hashable_strings(self) -> None:
        """``StrEnum`` is what makes these storable in a ``VARCHAR`` column and
        serialisable straight into JSON without a converter anywhere.

        The comparison goes through ``.value`` and ``str()`` rather than
        ``member == "literal"``, which mypy rejects as a non-overlapping equality
        check even though it holds at runtime.
        """
        permission = Permission.TRADE_EXECUTE_SELF
        assert isinstance(permission, str)
        assert permission.value == "trade:execute:self"
        assert str(permission) == "trade:execute:self"
        assert permission.name == "TRADE_EXECUTE_SELF"
        # Hashable and comparable as a set member, which is how grant sets work.
        assert {permission} == {Permission.TRADE_EXECUTE_SELF}
        assert permission in frozenset(Permission)


class TestOwnershipHierarchy:
    def test_the_owner_holds_every_permission(self) -> None:
        assert permissions_for(Role.OWNER) == frozenset(Permission)

    def test_admin_is_owner_minus_the_reserved_acts(self) -> None:
        assert permissions_for(Role.ADMIN) == frozenset(Permission) - OWNER_ONLY_PERMISSIONS

    def test_admin_is_strictly_less_than_owner(self) -> None:
        assert permissions_for(Role.ADMIN) < permissions_for(Role.OWNER)

    def test_exactly_two_acts_are_reserved_to_the_owner(self) -> None:
        assert {
            Permission.PLATFORM_TRANSFER_OWNERSHIP,
            Permission.AUDIT_ARCHIVE,
        } == OWNER_ONLY_PERMISSIONS

    def test_no_other_role_holds_an_owner_only_permission(self) -> None:
        for role in ALL_ROLES:
            if role is Role.OWNER:
                continue
            assert not (OWNER_ONLY_PERMISSIONS & permissions_for(role)), role

    def test_no_role_exceeds_the_owner(self) -> None:
        for role in ALL_ROLES:
            assert permissions_for(role) <= permissions_for(Role.OWNER)


class TestSelfServiceIsUniversal:
    @pytest.mark.parametrize("role", ALL_ROLES)
    def test_every_role_can_manage_its_own_account(self, role: Role) -> None:
        """A ``VIEWER`` who cannot sign out or change their password has to ask an
        administrator for basic account hygiene — and support tickets are how
        self-service turns into privilege escalation."""
        assert permissions_for(role) >= SELF_SERVICE_PERMISSIONS

    @pytest.mark.parametrize("role", ALL_ROLES)
    def test_every_role_can_end_its_own_session(self, role: Role) -> None:
        assert role_has_permission(role, Permission.SESSION_REVOKE_SELF)

    def test_the_self_service_set_is_only_about_the_caller(self) -> None:
        """It is granted to *every* role including customers, so it must contain
        nothing that reaches another account."""
        assert SELF_SERVICE_PERMISSIONS
        for permission in SELF_SERVICE_PERMISSIONS:
            assert permission.value.endswith(":self") or permission is Permission.SYSTEM_READ

    def test_a_customer_role_can_delete_its_own_account(self) -> None:
        """Refusing this would force a user to open a ticket to exercise a right
        over their own account."""
        for role in CUSTOMER_ROLES:
            assert role_has_permission(role, Permission.ACCOUNT_DELETE_SELF)


class TestCustomerRolesCannotReachOtherAccounts:
    @pytest.mark.parametrize("role", CUSTOMER_ROLES)
    def test_no_cross_account_permission(self, role: Role) -> None:
        """The single most important boundary in the catalogue.

        One ``user:read:any`` added to ``TRADER`` "to make the admin screen work"
        would be a full cross-tenant data leak, and it would not raise, crash or
        fail any happy-path test.
        """
        granted = permissions_for(role)
        cross_account = {p.value for p in granted if p.value.endswith(":any")}
        assert not cross_account, f"{role} holds {cross_account}"

    @pytest.mark.parametrize("role", CUSTOMER_ROLES)
    def test_no_administration_of_accounts(self, role: Role) -> None:
        forbidden = {
            Permission.USER_CREATE,
            Permission.USER_READ_ANY,
            Permission.USER_UPDATE_ANY,
            Permission.USER_SUSPEND,
            Permission.USER_DELETE_ANY,
            Permission.SESSION_READ_ANY,
            Permission.SESSION_REVOKE_ANY,
            Permission.PASSWORD_RESET_ANY,
            Permission.ROLE_READ,
            Permission.ROLE_ASSIGN,
            Permission.AUDIT_READ,
            Permission.AUDIT_EXPORT,
            Permission.SECURITY_READ,
            Permission.SECURITY_RESPOND,
            Permission.SYSTEM_READ_INTERNAL,
            Permission.FEATURE_FLAG_READ,
            Permission.FEATURE_FLAG_UPDATE,
            Permission.KILL_SWITCH_ACTIVATE,
        }
        assert not (forbidden & permissions_for(role))

    @pytest.mark.parametrize("role", CUSTOMER_ROLES)
    def test_every_mutation_is_scoped_to_self(self, role: Role) -> None:
        for permission in permissions_for(role):
            resource, action, *scope = permission.value.split(":")
            if action in {"read"}:
                continue
            assert scope == ["self"], f"{role} holds unscoped mutation {permission.value}"
            assert resource

    def test_unscoped_permissions_are_staff_only(self) -> None:
        """An unscoped permission is inherently platform-wide — ``audit:read`` does
        not mean "your own audits" — so a customer role holding one would be a leak
        that the ``:any`` check above cannot see.

        The two exceptions are named in :data:`PUBLIC_PERMISSIONS`: market data and
        public system status belong to nobody and are served without authentication.
        Everything else that is unscoped must stay with staff.
        """
        unscoped = {
            permission
            for permission in Permission
            if not permission.value.endswith((":self", ":any", ":internal"))
        }
        assert Permission.AUDIT_READ in unscoped
        assert Permission.USER_CREATE in unscoped
        assert unscoped > PUBLIC_PERMISSIONS
        for role in CUSTOMER_ROLES:
            assert (unscoped & permissions_for(role)) <= PUBLIC_PERMISSIONS, role

    def test_administrative_permissions_never_reach_a_customer_role(self) -> None:
        """The concrete form of the rule above, spelled out so a reviewer can see
        exactly which grants would be catastrophic."""
        administrative = {
            Permission.AUDIT_READ,
            Permission.AUDIT_EXPORT,
            Permission.AUDIT_ARCHIVE,
            Permission.USER_CREATE,
            Permission.USER_UPDATE_ANY,
            Permission.USER_SUSPEND,
            Permission.ROLE_READ,
            Permission.ROLE_ASSIGN,
            Permission.SECURITY_READ,
            Permission.SECURITY_RESPOND,
            Permission.FEATURE_FLAG_UPDATE,
            Permission.METRICS_READ,
            Permission.SYSTEM_READ_INTERNAL,
            Permission.KILL_SWITCH_ACTIVATE,
            Permission.PLATFORM_TRANSFER_OWNERSHIP,
        }
        for role in CUSTOMER_ROLES:
            assert not (administrative & permissions_for(role)), role

    def test_internal_scope_is_not_a_customer_permission(self) -> None:
        for role in CUSTOMER_ROLES:
            assert not role_has_permission(role, Permission.SYSTEM_READ_INTERNAL)

    def test_staff_roles_are_identified(self) -> None:
        assert {
            Role.OWNER,
            Role.ADMIN,
            Role.COMPLIANCE_OFFICER,
            Role.SUPPORT_AGENT,
            Role.RISK_MANAGER,
        } == STAFF_ROLES
        assert {role for role in ALL_ROLES if is_staff(role)} == STAFF_ROLES
        assert not any(is_staff(role) for role in CUSTOMER_ROLES)


class TestLeastPrivilegePerStaffRole:
    def test_compliance_may_only_read(self) -> None:
        """An auditor who can also act is not an auditor (§41, §44).

        The self-service permissions are excluded because a compliance officer must
        still be able to change their own password; everything beyond that is read.
        """
        beyond_self = permissions_for(Role.COMPLIANCE_OFFICER) - SELF_SERVICE_PERMISSIONS
        actions = {permission.value.split(":")[1] for permission in beyond_self}
        assert actions <= {"read", "export"}

    def test_compliance_can_investigate_but_not_intervene(self) -> None:
        grants = permissions_for(Role.COMPLIANCE_OFFICER)
        assert Permission.AUDIT_READ in grants
        assert Permission.AUDIT_EXPORT in grants
        assert Permission.USER_READ_ANY in grants
        assert Permission.TRADE_READ_ANY in grants
        for forbidden in (
            Permission.USER_SUSPEND,
            Permission.USER_UPDATE_ANY,
            Permission.SESSION_REVOKE_ANY,
            Permission.PASSWORD_RESET_ANY,
            Permission.ROLE_ASSIGN,
            Permission.FEATURE_FLAG_UPDATE,
            Permission.KILL_SWITCH_ACTIVATE,
            Permission.TRADE_EXECUTE_SELF,
            Permission.SECURITY_RESPOND,
            Permission.AUDIT_ARCHIVE,
        ):
            assert forbidden not in grants

    def test_support_can_diagnose_and_end_sessions_only(self) -> None:
        grants = permissions_for(Role.SUPPORT_AGENT)
        assert Permission.USER_READ_ANY in grants
        assert Permission.SESSION_READ_ANY in grants
        assert Permission.SESSION_REVOKE_ANY in grants
        assert Permission.PASSWORD_RESET_ANY in grants

    def test_support_cannot_trade_or_grant(self) -> None:
        """The one write a support agent holds is a password reset, which is
        audited. Nothing here lets them act as the customer."""
        grants = permissions_for(Role.SUPPORT_AGENT)
        for forbidden in (
            Permission.TRADE_EXECUTE_SELF,
            Permission.LIVE_TRADING_ACTIVATE_SELF,
            Permission.LIVE_TRADING_ACTIVATE_ANY,
            Permission.EXCHANGE_READ_ANY,
            Permission.EXCHANGE_CONNECT_SELF,
            Permission.ROLE_ASSIGN,
            Permission.USER_UPDATE_ANY,
            Permission.USER_SUSPEND,
            Permission.USER_DELETE_ANY,
            Permission.FEATURE_FLAG_UPDATE,
            Permission.RISK_UPDATE_ANY,
            Permission.KILL_SWITCH_ACTIVATE,
            Permission.BOT_MANAGE_ANY,
            Permission.AUDIT_EXPORT,
            Permission.SECURITY_RESPOND,
        ):
            assert forbidden not in grants, forbidden

    def test_risk_can_stop_anything(self) -> None:
        grants = permissions_for(Role.RISK_MANAGER)
        assert Permission.KILL_SWITCH_ACTIVATE in grants
        assert Permission.RISK_UPDATE_ANY in grants
        assert Permission.BOT_MANAGE_ANY in grants
        assert Permission.SECURITY_RESPOND in grants

    def test_risk_cannot_start_anything(self) -> None:
        """Deliberate asymmetry: a risk officer may halt trading but may not enable
        live trading or place an order (§26, §31)."""
        grants = permissions_for(Role.RISK_MANAGER)
        for forbidden in (
            Permission.LIVE_TRADING_ACTIVATE_ANY,
            Permission.LIVE_TRADING_ACTIVATE_SELF,
            Permission.TRADE_EXECUTE_SELF,
            Permission.EXCHANGE_CONNECT_SELF,
            Permission.ROLE_ASSIGN,
            Permission.USER_SUSPEND,
            Permission.USER_DELETE_ANY,
            Permission.PASSWORD_RESET_ANY,
            Permission.SESSION_REVOKE_ANY,
            Permission.FEATURE_FLAG_UPDATE,
            Permission.AUDIT_ARCHIVE,
        ):
            assert forbidden not in grants, forbidden

    def test_only_three_roles_hold_the_kill_switch(self) -> None:
        holders = {
            role for role in ALL_ROLES if role_has_permission(role, Permission.KILL_SWITCH_ACTIVATE)
        }
        assert holders == {Role.OWNER, Role.ADMIN, Role.RISK_MANAGER}

    def test_only_owner_and_admin_can_enable_live_trading_for_others(self) -> None:
        holders = {
            role
            for role in ALL_ROLES
            if role_has_permission(role, Permission.LIVE_TRADING_ACTIVATE_ANY)
        }
        assert holders == {Role.OWNER, Role.ADMIN}

    def test_only_owner_and_admin_assign_roles(self) -> None:
        holders = {role for role in ALL_ROLES if role_has_permission(role, Permission.ROLE_ASSIGN)}
        assert holders == {Role.OWNER, Role.ADMIN}

    def test_only_owner_and_admin_change_feature_flags(self) -> None:
        holders = {
            role for role in ALL_ROLES if role_has_permission(role, Permission.FEATURE_FLAG_UPDATE)
        }
        assert holders == {Role.OWNER, Role.ADMIN}


class TestViewerIsReadOnly:
    def test_a_viewer_changes_nothing_but_their_own_account(self) -> None:
        beyond_self = (
            permissions_for(Role.VIEWER)
            - SELF_SERVICE_PERMISSIONS
            - {Permission.ACCOUNT_DELETE_SELF}
        )
        assert {permission.value.split(":")[1] for permission in beyond_self} == {"read"}

    def test_a_viewer_cannot_trade_or_configure(self) -> None:
        grants = permissions_for(Role.VIEWER)
        for forbidden in (
            Permission.TRADE_EXECUTE_SELF,
            Permission.BOT_MANAGE_SELF,
            Permission.EXCHANGE_CONNECT_SELF,
            Permission.EXCHANGE_DISCONNECT_SELF,
            Permission.RISK_UPDATE_SELF,
            Permission.BACKTEST_RUN_SELF,
            Permission.NOTIFICATION_MANAGE_SELF,
            Permission.LIVE_TRADING_ACTIVATE_SELF,
            Permission.KILL_SWITCH_ACTIVATE,
        ):
            assert forbidden not in grants, forbidden

    def test_a_viewer_sees_what_a_trader_sees(self) -> None:
        """Read-only means no control, not less visibility."""
        trader_reads = {p for p in permissions_for(Role.TRADER) if p.value.split(":")[1] == "read"}
        assert trader_reads <= permissions_for(Role.VIEWER)


class TestTraderIsAFullCustomer:
    def test_a_trader_can_operate_their_own_trading(self) -> None:
        grants = permissions_for(Role.TRADER)
        for expected in (
            Permission.EXCHANGE_CONNECT_SELF,
            Permission.BOT_MANAGE_SELF,
            Permission.TRADE_EXECUTE_SELF,
            Permission.LIVE_TRADING_ACTIVATE_SELF,
            Permission.RISK_UPDATE_SELF,
            Permission.BACKTEST_RUN_SELF,
        ):
            assert expected in grants

    def test_a_trader_holds_strictly_more_than_a_viewer(self) -> None:
        assert permissions_for(Role.VIEWER) < permissions_for(Role.TRADER)


class TestUnknownInputFailsClosed:
    @pytest.mark.parametrize("unknown", ["GHOST", "owner", "Trader", "", "ADMIN ", "superuser"])
    def test_an_unknown_role_grants_nothing(self, unknown: str) -> None:
        """Authorization asks "may this caller act?"; for a role nobody recognises
        the only safe answer is no. Raising would turn one bad row into a 500 on
        every request that account makes (§43)."""
        assert permissions_for(unknown) == frozenset()
        assert is_staff(unknown) is False
        assert role_has_permission(unknown, Permission.ACCOUNT_READ_SELF) is False

    @pytest.mark.parametrize("unknown", [None, 12345, object()])
    def test_a_non_string_role_grants_nothing(self, unknown: object) -> None:
        assert permissions_for(unknown) == frozenset()  # type: ignore[arg-type]
        assert is_staff(unknown) is False  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "unknown", ["nope:nope:nope", "TRADE_EXECUTE_SELF", "", "trade:execute", "trade:self"]
    )
    def test_an_unknown_permission_is_never_granted(self, unknown: str) -> None:
        assert role_has_permission(Role.OWNER, unknown) is False

    def test_a_known_permission_is_granted_by_name_or_value(self) -> None:
        assert role_has_permission(Role.TRADER, Permission.TRADE_EXECUTE_SELF) is True
        assert role_has_permission(Role.TRADER, "trade:execute:self") is True
        assert role_has_permission("TRADER", "trade:execute:self") is True
        assert role_has_permission("VIEWER", "trade:execute:self") is False

    def test_grant_sets_cannot_be_mutated_by_a_caller(self) -> None:
        """A shared ``set`` could be widened at runtime by any code that gets it."""
        grants = permissions_for(Role.VIEWER)
        assert isinstance(grants, frozenset)
        with pytest.raises(AttributeError):
            grants.add(Permission.ROLE_ASSIGN)  # type: ignore[attr-defined]


class TestRegistrationDefault:
    def test_the_default_role_is_a_customer_role(self) -> None:
        """Nothing about signing up may confer platform authority (§41)."""
        assert default_role() is Role.TRADER
        assert is_staff(default_role()) is False

    def test_the_default_role_has_no_cross_account_power(self) -> None:
        assert not any(p.value.endswith(":any") for p in permissions_for(default_role()))

    def test_no_staff_role_is_a_registration_default(self) -> None:
        assert default_role() not in STAFF_ROLES

    def test_the_default_role_can_actually_use_the_product(self) -> None:
        """A default that could not trade would push new users toward asking an
        administrator for an upgrade — the pattern least privilege exists to avoid."""
        assert role_has_permission(default_role(), Permission.TRADE_EXECUTE_SELF)
        assert role_has_permission(default_role(), Permission.EXCHANGE_CONNECT_SELF)
