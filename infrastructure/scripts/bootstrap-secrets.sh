#!/usr/bin/env bash
# =============================================================================
#  Generate a populated .env from .env.example (§89, §90, §133)
# =============================================================================
#  Usage:
#      infrastructure/scripts/bootstrap-secrets.sh            # create .env
#      infrastructure/scripts/bootstrap-secrets.sh --force    # overwrite
#      infrastructure/scripts/bootstrap-secrets.sh --print    # to stdout, no file
#
#  Every CHANGE_ME placeholder is replaced with a cryptographically strong
#  value from Python's `secrets` module. The script never prints a generated
#  secret to the terminal unless --print is passed explicitly, and the file it
#  writes is mode 0600.
#
#  Passwords use URL-safe base64 (A-Z a-z 0-9 - _). That is a deliberate
#  constraint rather than a convenience: a generated password containing `@`,
#  `/` or `:` would corrupt the DATABASE_URL it is embedded in, producing a
#  connection string that parses to the wrong host and fails in a way that looks
#  like a network problem.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEMPLATE="$REPO_ROOT/.env.example"
TARGET="$REPO_ROOT/.env"

FORCE=0
PRINT=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --print) PRINT=1 ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown option: $arg (try --help)" >&2
            exit 2
            ;;
    esac
done

if [[ ! -f "$TEMPLATE" ]]; then
    echo "template not found: $TEMPLATE" >&2
    exit 1
fi

if [[ -e "$TARGET" && "$FORCE" -eq 0 && "$PRINT" -eq 0 ]]; then
    cat >&2 <<MSG
refusing to overwrite $TARGET

That file may hold credentials a database has already been initialised with.
Re-running with --force would replace the database password while PostgreSQL
still expects the old one, leaving a stack that cannot connect.

To rotate deliberately:  $0 --force
To preview only:        $0 --print
MSG
    exit 1
fi

# Prefer the project virtualenv's interpreter, but do not require it: this script
# is the first thing a fresh clone runs, possibly before `make install`.
PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" && -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON="$REPO_ROOT/.venv/bin/python"
elif [[ -z "$PYTHON" ]]; then
    if command -v python3 >/dev/null 2>&1; then
        PYTHON=python3
    else
        echo "python3 is required to generate secrets" >&2
        exit 1
    fi
fi

render() {
    TEMPLATE_PATH="$TEMPLATE" "$PYTHON" - <<'PY'
import os
import secrets
from pathlib import Path

def generate_fernet_key() -> str:
    """A url-safe base64-encoded 32-byte key.

    Uses `cryptography.fernet` when it is importable, because that guarantees
    the key is one arb_core.config will accept. Falls back to constructing the
    identical format by hand: this script is often the first thing run on a
    fresh clone, before the virtualenv exists, and requiring the project's own
    dependencies to bootstrap its configuration would be circular.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        import base64

        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    return Fernet.generate_key().decode()


template = Path(os.environ["TEMPLATE_PATH"]).read_text()

# A DSN-embedded password must not contain URL-significant characters.
db_password = secrets.token_urlsafe(24)
telegram_token = f"{secrets.randbelow(900_000_000) + 100_000_000}:{secrets.token_urlsafe(35)}"

replacements = {
    # The same value appears in DATABASE_URL, DATABASE_MIGRATION_URL and
    # POSTGRES_PASSWORD; one replacement keeps all three consistent.
    "CHANGE_ME_db_password": db_password,
    "CHANGE_ME_jwt_secret_min_64_chars_long_random_string_aaaaaaaaaaaaaaaaaaaa": (
        secrets.token_urlsafe(64)
    ),
    "CHANGE_ME_session_secret_min_64_chars_long_random_string_aaaaaaaaaaaaaaaa": (
        secrets.token_urlsafe(64)
    ),
    "CHANGE_ME_smtp_password": secrets.token_urlsafe(24),
    "CHANGE_ME_telegram_bot_token": telegram_token,
    "CHANGE_ME_grafana_password": secrets.token_urlsafe(24),
    # .env.example ships a well-known development Fernet key so a fresh clone
    # works immediately. arb_core.config rejects that exact value in production,
    # so a deployment that forgot to rotate it fails at startup rather than
    # encrypting credentials under a public key.
    "db4D7xAh6Dn9sk-oUr0U2mQ_uGYIxZmxIKFF53hShKA=": generate_fernet_key(),
}

for needle, value in replacements.items():
    template = template.replace(needle, value)

# Scan assignment values only. The template's own prose explains that "every
# placeholder marked CHANGE_ME must be replaced", and a guard that fires on that
# sentence would train whoever runs it to ignore the guard.
DEV_FERNET_KEY = "db4D7xAh6Dn9sk-oUr0U2mQ_uGYIxZmxIKFF53hShKA="
leftover = []
for line in template.splitlines():
    stripped = line.lstrip()
    if stripped.startswith("#") or "=" not in stripped:
        continue
    key, _, value = stripped.partition("=")
    if "CHANGE_ME" in value or DEV_FERNET_KEY in value:
        leftover.append(key.strip())
if leftover:
    raise SystemExit(f"unreplaced placeholders in: {sorted(set(leftover))}")

print(template, end="")
PY
}

if [[ "$PRINT" -eq 1 ]]; then
    render
    exit 0
fi

# 0600 before the first byte is written, so the file is never briefly readable.
umask 177
render > "$TARGET"
chmod 600 "$TARGET"

echo "wrote $TARGET (mode 600)"
echo "generated: POSTGRES_PASSWORD, DATABASE_URL, DATABASE_MIGRATION_URL,"
echo "           JWT_SECRET, SESSION_SECRET, ENCRYPTION_KEY,"
echo "           SMTP_PASSWORD, TELEGRAM_BOT_TOKEN, GRAFANA_ADMIN_PASSWORD"
echo
echo "next:  make up      (build, migrate, start the stack)"
