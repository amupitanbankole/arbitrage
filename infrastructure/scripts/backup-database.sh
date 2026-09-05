#!/usr/bin/env bash
# =============================================================================
#  Consistent PostgreSQL dump (§88)
# =============================================================================
#  Usage:
#      infrastructure/scripts/backup-database.sh [output-file]
#
#  Default output: backups/arbitrage-<UTC timestamp>.dump
#
#  This dumps the *source of truth* (§64). Redis holds no data worth backing up:
#  it is cache, pub/sub and locks, and a restored lock would be a lock nobody
#  holds — actively dangerous rather than merely stale.
#
#  `pg_dump` runs inside the container so the dump is produced by the server's
#  own client version, and `-Fc` (custom format) is used because it is
#  compressed and supports selective restore.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/infrastructure/docker/docker-compose.yml"
ENV_FILE="$REPO_ROOT/.env"
CONTAINER="${POSTGRES_CONTAINER:-arbitrage-platform-postgres-1}"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT="${1:-$REPO_ROOT/backups/arbitrage-$TIMESTAMP.dump}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "missing $ENV_FILE — run infrastructure/scripts/bootstrap-secrets.sh first" >&2
    exit 1
fi

# Sourced only to read POSTGRES_USER / POSTGRES_DB. The file is 0600 and its
# values are never echoed.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    echo "postgres container '$CONTAINER' is not running" >&2
    echo "start it with: docker compose -f $COMPOSE_FILE up -d postgres" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

echo "dumping ${POSTGRES_DB} from ${CONTAINER} -> ${OUTPUT}"

# Written to stdout and redirected on the host, so nothing lands inside the
# container's filesystem (which is read-only for the application services).
docker exec "$CONTAINER" \
    pg_dump --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --format=custom --no-owner \
    > "$OUTPUT"

chmod 600 "$OUTPUT"

SIZE="$(du -h "$OUTPUT" | cut -f1)"
echo "wrote $OUTPUT ($SIZE, mode 600)"

# A dump that cannot be restored is not a backup. Reading the archive header
# proves pg_dump produced a valid custom-format file rather than an error page.
if ! docker exec -i "$CONTAINER" pg_restore --list < "$OUTPUT" > /dev/null; then
    echo "WARNING: $OUTPUT did not validate with pg_restore --list" >&2
    exit 1
fi
echo "validated: pg_restore --list succeeded"
echo
echo "restore with:"
echo "  docker exec -i $CONTAINER pg_restore --username $POSTGRES_USER \\"
echo "      --dbname $POSTGRES_DB --clean --if-exists --no-owner < $OUTPUT"
