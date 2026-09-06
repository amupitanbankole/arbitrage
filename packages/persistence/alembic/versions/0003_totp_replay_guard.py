"""users.totp_last_used_step: reject a reused TOTP code

Phase 2 (§59). RFC 6238 §5.2.

Why a column and not a cache
----------------------------
A time-based code is valid for a whole step — 30 seconds by default — and the
platform accepts one step of drift either side so that a phone with a slightly
wrong clock still works. That tolerance is necessary and it is also an attack
surface: a code seen once can be presented again inside the window it belongs to.

RFC 6238 §5.2 is explicit that this must not be allowed — "The verifier MUST NOT
accept the second attempt of the OTP after the successful validation" — so the step
of the most recently accepted code is recorded and a repeat is rejected.

The value lives in ``users`` rather than in Redis because it is a security control,
and Redis is a cache (§10, §12). A control held in a cache fails *open*: when Redis
is unreachable the check has to be skipped or every MFA login fails, and an operator
who chooses "skip" has just removed the control at the moment an attacker is most
likely to be exercising it. A nullable column on a row the login already reads costs
one ``UPDATE`` on a path that already writes the session, and it survives a cache
flush, a restart and a failover.

Backfill
--------
``NULL`` means "no code has been accepted yet", which is the correct starting state
for every existing account: the column is added nullable so the migration needs no
table rewrite, and the first successful verification populates it.

The ``CHECK`` mirrors ``ck_users_failed_login_count_non_negative``. A step is
``unix_seconds // period``, which cannot be negative; the constraint exists because
a negative value would be a bug in the caller rather than a state the database
should store, and because it makes the column's meaning readable from the schema
alone.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Full name, matching what the naming convention renders for the model-level
#: ``CheckConstraint("totp_last_used_step >= 0", name="totp_last_used_step_non_negative")``.
#: Alembic operations do not apply the MetaData naming convention, so the migration
#: spells out the name the ORM would have generated.
_CHECK_NAME: str = "ck_users_totp_last_used_step_non_negative"


def _is_postgresql() -> bool:
    """Whether the target supports ``ALTER TABLE ... ADD CONSTRAINT``.

    Same guard, and same reason, as the audit-immutability trigger in ``0001``:
    PostgreSQL is the only supported production database (§10), while SQLite — used
    by the migration suite and by local development — cannot add a constraint to an
    existing table at all.

    ``op.get_bind()`` reports the right dialect in offline ``--sql`` mode too, so
    ``alembic upgrade head --sql`` still produces reviewable DDL. The alternative,
    Alembic's batch copy-and-move mode, cannot: reflecting the table it is rewriting
    needs a live connection, so batch mode turns offline SQL generation into a
    ``CommandError``. Passing ``copy_from`` would work, but it means restating every
    column of ``users`` inside this revision — and a column omitted from that list is
    a column the copy-and-move silently drops.
    """
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    """Add the replay-guard column and its constraint."""
    op.add_column("users", sa.Column("totp_last_used_step", sa.BigInteger(), nullable=True))
    if _is_postgresql():
        op.create_check_constraint(_CHECK_NAME, "users", "totp_last_used_step >= 0")


def downgrade() -> None:
    """Remove the replay guard.

    Downgrading re-opens the reuse window described above; that is a real loss of a
    security property, and it is called out here so the decision is not taken by
    somebody who only read the revision list.
    """
    if _is_postgresql():
        op.drop_constraint(_CHECK_NAME, "users", type_="check")
    op.drop_column("users", "totp_last_used_step")
