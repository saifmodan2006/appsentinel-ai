# Deployment

## Local

Use Docker Compose as described in the root README. The web gateway binds to loopback by default. API and PostgreSQL have no published ports. Docker Desktop needs Linux containers. Let the initial image build finish before investigating application health.

## Controlled remote deployment

1. Use a dedicated Linux host with Docker Engine, Compose v2, adequate volume capacity, and monitored resource limits. Install a trusted HTTPS reverse proxy on that host. Route public TLS traffic to the Compose gateway on loopback. Keep the API and database internal to Compose.
2. Store a unique HTTPS-safe database password in a restricted `.env` file. Set `SENTINEL_SECURE_COOKIE=true` and `SENTINEL_ALLOW_REGISTER=false`. Set network-level connection and request limits at the public proxy. The Compose gateway and API also enforce their own limits. If the proxy address is shared, current backend IP reset windows apply to that address. Deployment operators should adapt the trusted-proxy and rate-limit configuration to the actual topology.
3. Use a hostname and certificate trusted by browser and Android clients. Create accounts with `docker compose exec api python -m sentinel.accounts create-user <email>`. Bootstrap one administrator with `create-admin`.
4. Run the verification suite against a staging deployment. Check database persistence, scanner network isolation, scan expiry, proxy upload limits, TLS, authentication, scope of registration, and container image advisories.
5. Back up PostgreSQL independently of the ephemeral upload and exchange volumes. Verify restore into a separate instance and keep encrypted backup retention consistent with policy.

Example GNU/Linux backup and restore statements:

```sh
umask 077
docker compose exec -T db pg_dump -U sentinel -d sentinel -Fc > sentinel.dump
pg_restore --list sentinel.dump
# Restore into a fresh, operator-created staging database:
pg_restore --exit-on-error --dbname "$STAGING_DATABASE_URL" sentinel.dump
```

Optional evidence artifacts can be placed in an operator-readable `data/evidence` directory and mounted read-only. Run `docker compose -f compose.yaml -f compose.evidence.yaml up -d --build --wait`. Set paths with the container prefix `/evidence/` and independently set their checksums in `.env`.

## Hosted demonstration

Render documents free web service sleep and platform restarts, an expiring free PostgreSQL database, and paid workers and persistent disks. That tier would require a separately hosted scanner and backing store for a full upload workflow. Cloudflare Pages can host static assets, but the browser currently uses same-origin credentials and requires a gateway that serves both the dashboard and API paths. Use the local stack for a full no-cost demonstration. Remote deployment needs a host, DNS and TLS ownership, and applicable service permissions. [Render free-tier documentation](https://render.com/docs/free) · [Cloudflare Pages documentation](https://developers.cloudflare.com/pages/)
