# PostgreSQL container

**There is no schema initialisation script in this directory, and that is the
point.**

Every table, index and constraint is created by an Alembic revision under
`packages/persistence/alembic/versions/`, applied by the `migrate` service in
`docker-compose.yml` before the API or worker starts (§44, §141).

An `initdb.d/*.sql` script here would be executed by the `postgres:16-alpine`
image **only when the data volume is empty**. That produces two failure modes
worth avoiding explicitly:

1. A table created here and also created by a migration diverges the first time
   either changes — and only on hosts where the volume happened to be fresh.
2. On an existing deployment the script silently does not run, so the schema
   depends on when the volume was created rather than on the revision chain.

`POSTGRES_DB`, `POSTGRES_USER` and `POSTGRES_PASSWORD` are the container's
business: they create the role and the empty database that migrations then own.

## Connecting from the host

`docker-compose.yml` publishes `5432` on `127.0.0.1` only, so a local client
connects with the same credentials in `.env`:

```bash
psql "postgresql://arbitrage:$(grep -m1 '^POSTGRES_PASSWORD=' .env | cut -d= -f2)@127.0.0.1:5432/arbitrage"
```

Inside the compose network the host name is `postgres`, never `localhost`.

## Backup

`infrastructure/scripts/backup-database.sh` takes a consistent dump using
`pg_dump` inside the running container. A dump is the only backup that survives
losing the volume; see that script for the restore command.
