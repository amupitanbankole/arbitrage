# nginx

The platform's only publicly exposed listener (§87, §88, §124).

| File | Loaded? | Purpose |
| --- | --- | --- |
| `nginx.conf` | yes (mounted read-only) | `http` block: logging, limits, upstream, `server_tokens off` |
| `conf.d/00-http.conf` | yes | Port 80 server: proxy to the API, refuse `/metrics`, `/docs`, dotfiles |
| `conf.d/tls.conf.example` | **no** | Template for a 443 listener with HSTS |
| `ssl/` | git-ignored (`*.pem`, `*.crt`, `*.key`) | Certificate and key, mounted only when TLS is enabled |

## What nginx does and does not add

**Security headers are set by the application, not here.** Every response the
API produces — including the 500 for an unhandled exception — already carries
the full platform header set (`arb_api.middleware.security_headers`,
`arb_api.middleware.error_handlers`). Using `add_header` in nginx would emit a
*second* `Content-Security-Policy`, and browsers enforce the intersection of
duplicated headers, which breaks a policy that was working.

The single exception is `Strict-Transport-Security`, configured in
`tls.conf.example`: HSTS is a property of a TLS listener, and sending it from a
plain-HTTP development instance would pin a browser to HTTPS for a domain it
does not own.

nginx does own:

* `server_tokens off` — no version in the `Server` header (§124).
* `return 404` for `/metrics`, `/docs`, `/redoc`, `/openapi.json` and dotfiles.
  404 rather than 403, so the response does not confirm the path exists.
* A coarse `limit_req` zone as a first line of defence. Per-user and
  per-endpoint limits belong to the application (§76).

## Enabling TLS

```bash
cd infrastructure/docker/nginx
cp /path/to/fullchain.pem /path/to/privkey.pem ssl/
cp conf.d/tls.conf.example conf.d/10-tls.conf
$EDITOR conf.d/10-tls.conf          # set server_name to your real domain
```

Then in `infrastructure/docker/docker-compose.yml`, on the `nginx` service:
uncomment the `./nginx/ssl` volume mount and the `"443:443"` port mapping, and
`docker compose -f infrastructure/docker/docker-compose.yml exec nginx nginx -t`
to validate before reloading.

When TLS is live, `conf.d/00-http.conf` should be removed or reduced to the
`/nginx-health` location: leaving both an HTTP proxy and an HTTPS redirect means
the same content is served on both, and only one of them gets HSTS.

## Validating a configuration change

Always test before reloading — an nginx that fails to parse its configuration
exits, and the whole public edge disappears with it:

```bash
docker compose -f infrastructure/docker/docker-compose.yml exec nginx nginx -t
docker compose -f infrastructure/docker/docker-compose.yml exec nginx nginx -s reload
```
