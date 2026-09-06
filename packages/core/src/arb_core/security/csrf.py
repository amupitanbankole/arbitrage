"""CSRF protection (§59, §61).

The platform authenticates two ways: an ``Authorization: Bearer`` access token and
a cookie pair (refresh + CSRF). Only the cookie path needs CSRF defence, because a
browser attaches cookies to a cross-site request automatically while it will not
invent an ``Authorization`` header. Enforcing CSRF on bearer requests would add a
failure mode for mobile and server clients that cannot be attacked this way.

The scheme is double-submit, with the submitted token **bound to the session and
signed**:

1. On login the server sets ``arb_csrf`` — readable by the site's own JavaScript,
   so it is *not* ``HttpOnly``.
2. The client sends it back in ``X-CSRF-Token`` on every state-changing request.
3. The server recomputes ``HMAC-SHA256(session_secret, "arb-csrf-v1:" + session_id)``
   for the session it just authenticated, and compares in constant time.

Signing rather than storing a random token buys two things. There is no database or
Redis read on every mutating request, and — the part that matters — a token is
useless without the session it was issued for. Plain double-submit is weak against
cookie tossing, where an attacker who controls any subdomain sets a ``arb_csrf``
cookie of their own choosing and submits the matching header; the pair is consistent,
so the check passes. Here the attacker would have to know the victim's *session id*
to forge a matching token, and forging one for their own session does nothing,
because the value compared against is derived from the session the request actually
authenticated as.

The token is deterministic for a session, so the same value is returned on every
refresh of that session and the client never has to reconcile two. It changes when
the session changes — a new login produces a new session id and therefore a new
token, and a rotated refresh token rotates it too.

Two deliberate choices worth stating, because both look like omissions:

* **The token is not stored.** Nothing to revoke, nothing to expire out of step
  with the session it protects, and an attacker with database read access gains no
  CSRF tokens they did not already have.
* **A missing token and a wrong token are the same answer.** :meth:`CsrfProtector.verify`
  returns ``False`` for absent, empty, malformed and incorrect values alike, and the
  caller raises one :class:`~arb_core.errors.CsrfError`. Telling a client "you sent
  no token" versus "you sent a bad token" is a hint an attacker can use to probe the
  scheme, and no legitimate client needs the distinction (§71).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import TYPE_CHECKING, Final
from uuid import UUID

from arb_core.security.tokens import secrets_equal

if TYPE_CHECKING:
    from arb_core.config import Settings

__all__ = ["CsrfProtector"]

#: Domain separation. The session secret signs other things; prefixing the message
#: means a MAC computed for one purpose can never be replayed as a CSRF token.
_MAC_INFO: Final[bytes] = b"arb-csrf-v1:"


class CsrfProtector:
    """Issues and verifies session-bound CSRF tokens.

    Immutable and allocation-free per call beyond the HMAC itself, so one instance
    is built per process and shared.
    """

    __slots__ = ("_secret",)

    def __init__(self, *, secret: str) -> None:
        if not isinstance(secret, str) or not secret.strip():
            msg = "a CSRF signing secret is required"
            raise ValueError(msg)
        self._secret = secret.encode("utf-8")

    @classmethod
    def from_settings(cls, settings: Settings) -> CsrfProtector:
        """Build from configuration, using the **session** secret.

        Not the JWT secret: the two schemes must not share key material, so that
        a leak in one does not let an attacker mint tokens for the other (§60).
        """
        return cls(secret=settings.session_secret.get_secret_value())

    def issue(self, *, session_id: UUID | str) -> str:
        """Return the CSRF token for ``session_id``.

        Safe to place in a cookie: the token is a MAC output and carries no
        information about the session, the user or the secret.
        """
        return self._mac(_as_uuid(session_id, "session_id"))

    def verify(self, token: str | None, *, session_id: UUID | str | None) -> bool:
        """Return whether ``token`` is valid for ``session_id``.

        Never raises for bad input, because the inputs come straight off a request:
        an absent header, a truncated cookie and a hostile value are all ordinary.
        Every one of them is ``False``, and the caller turns that into a single
        :class:`~arb_core.errors.CsrfError`.

        An unauthenticated request (``session_id is None``) is always ``False``:
        there is no session to bind a token to, and treating "no session" as "no
        CSRF needed" would make dropping the session cookie a way past the check.
        """
        if session_id is None:
            return False
        if not isinstance(token, str):
            return False
        presented = token.strip()
        if not presented:
            return False
        return secrets_equal(self._mac(_as_uuid(session_id, "session_id")), presented)

    def _mac(self, session_id: UUID) -> str:
        """Compute the session-bound token."""
        digest = hmac.new(
            self._secret, _MAC_INFO + str(session_id).encode("utf-8"), hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def __repr__(self) -> str:
        # Never the secret: a repr can reach a log line through any exception
        # traceback that formats the object holding this one (§127).
        return "CsrfProtector(<configured>)"


def _as_uuid(value: object, field: str) -> UUID:
    """Coerce ``value`` to a :class:`UUID`, or raise a clear programming error."""
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            return UUID(value.strip())
        except ValueError as exc:
            msg = f"{field} is not a valid UUID"
            raise ValueError(msg) from exc
    msg = f"{field} must be a UUID or a string"
    raise TypeError(msg)
