# Changelog

All notable changes to **skein-web** (.NET 10 BFF / API gateway).

## [2.0.0] - 2026-11-22

- Security: the service routes of skein-api can no longer be reached from a
  browser. skein-web marks only its own calls to them with
  `X-Skein-Service-Call: 1` and never forwards that header; the proxy
  `/api/v1` answers `404` for paths under `auth/` (except `GET auth/me`),
  `hub/` and `internal/` in any spelling, before the session is checked and
  without calling skein-api (sk-940, sk-998).
- skein-web calls skein-api under `/ui/v1`. Browsers keep using `/api/v1`;
  skein-web rewrites the prefix, so open tabs keep working through the
  upgrade (sk-878.3.1).
- The proxy `/api/v1` no longer forwards the browser's `Cookie`,
  `Authorization`, `X-Forwarded-*` or `X-Real-IP` headers to skein-api
  (sk-977.7.91).
- Sign-in through proxy headers (`X-Auth-Request-*`, the legacy trust-headers
  mode) is accepted only from a peer listed in `SKEIN_TRUSTED_PROXIES`, judged
  by the address of the TCP connection; headers from any other peer are
  ignored with a warning. With an empty list nobody can sign in that way.
  Local sign-in and native OIDC are not affected (sk-977.7.12).
- Forwarded headers are processed once. `ASPNETCORE_FORWARDEDHEADERS_ENABLED`
  no longer has any effect; which proxies are trusted is decided only by
  `SKEIN_TRUSTED_PROXIES`, as before. Behind a chain of trusted proxies the
  client address is now read one hop deep instead of two (sk-977.7.12).
- New optional setting `SKEIN_ALLOWED_HOSTS`: the host names skein-web answers
  to. A request with another `Host`, or another `X-Forwarded-Host` from a
  trusted proxy, gets `400 invalid_host`; `/healthz`, `/ready` and `/metrics`
  are not checked. Left empty, any host name is accepted as before and a
  warning is logged at startup (sk-977.7.98).
- New session format. A session is stored in Redis under a new random key and
  the cookie is `__Host-skein.sid`: always `Secure`, `HttpOnly`, `Path=/`,
  `SameSite=Lax`, without `Domain`, whatever the scheme of the request.
  Sessions of the former format are removed once at startup, so everybody
  signs in again. For local development over plain http,
  `SKEIN_ALLOW_INSECURE_HTTP=true` (cookie `skein.sid` without `Secure`) works
  only with `ASPNETCORE_ENVIRONMENT=Development`; anywhere else it stops
  startup (sk-977.7.1, sk-977.7.14, sk-977.7.128).
- Every sign-in issues the session under a new key and revokes the key the
  request came with: password sign-in, sign-up, sign-up by invitation, the end
  of a password reset, native OIDC and proxy headers. A password reset revokes
  every session of the user before it issues the new one, and answers `204`
  only when all of them were revoked. API keys are not affected
  (sk-977.7.128).
- New `502` answers. When Redis cannot be read for a session, the request is
  answered `502` (`type .../upstream-unavailable`) before skein-api is called,
  without `Set-Cookie`; `/mcp` is not affected. When an account was created or
  a password was changed but the session could not be issued, the answer is
  `502` with `type .../account-created-session-not-issued` or
  `.../password-changed-session-not-issued`; the field `error` is
  `upstream_unavailable` in both, so tell them apart by `type` (sk-977.7.128).
- Live updates: signing out closes that session's hub connections on the same
  replica at once and on the others within 30 seconds; a user joins the
  administrators' group of the hub only when skein-api confirms the role; a
  project event whose project does not match its envelope is dropped
  (sk-977.7.92, sk-977.7.107, sk-977.7.108).
- Native OIDC: the return address of `/oauth2/start?rd=` must be a local path
  of the site; anything else returns to `/`. The OIDC session cookie stays a
  browser-session cookie (sk-977.7.34).
- Logs are logfmt up to warnings and JSON for errors, with a `service` field.
  Fields that look like secrets are masked, and proxied paths are logged with
  tokens masked and without the query string (sk-977.7.33).
- The image declares a healthcheck on `/healthz` and runs as the numeric user
  of the base image (UID 1654) instead of a user named by name. `/ready`
  answers `redis_unavailable` instead of the exception text. ASP.NET Core
  10.0.15 fixes CVE-2026-114147 (sk-977.7.35, sk-977.7.93, sk-977.7.106,
  sk-976.2).

### Upgrade notes

- **Stop both services, no rolling upgrade, no rollback.** This release and
  skein-api 2.0.0 work only with each other. Suspend GitOps reconciliation and
  automated image updates, stop every replica of skein-web and skein-api, and
  start the new images only when no old pod is `Running` or `Terminating`. In
  Kubernetes, roll skein-web out with the `Recreate` strategy
  (`deploy/kubernetes/skein-web.yaml` already does). See `DEPLOYMENT-NOTES.md`
  §4.7 of the Skein repository.
- Everybody signs in again after the upgrade.
- HTTPS is required: over plain http sign-in appears to succeed, but the
  browser drops the `Secure` cookie and there is no session; the skein-web log
  says why.
- Sign-in through proxy headers needs `SKEIN_TRUSTED_PROXIES` to list the
  address the proxy connects from. `ASPNETCORE_FORWARDEDHEADERS_ENABLED` can be
  removed.
- Set `SKEIN_ALLOWED_HOSTS` to the public host names (names only, no scheme,
  port or path). With a wrong list the pods stay ready, but every request gets
  `400 invalid_host`: check a request by the real name after the change.
- Log parsers that expect the former text format need to be updated. Volumes
  that only UID 1000 could use must allow UID 1654.
- If you ever roll skein-web back, delete the Redis key `skein:session-format`
  before you roll this version out again; sessions of this version that
  survived the rollback are then valid again.

## [1.0.1] - 2026-11-09

- Security: a change of a user's role, name or username, or the user's
  deactivation, now reliably ends that user's existing browser sessions. Before
  this release, the live-update bridge could take such an event and discard it,
  so the sessions stayed valid; in local and native OIDC sign-in no periodic
  check caught this. Session revocation now has its own NATS queue group (sk-632).
- Native OIDC sign-in keeps a `403 user_not_provisioned` answer from skein-api
  instead of turning it into `502 sso_provisioning_failed`, also for unknown
  users when automatic provisioning is off. Access is denied and no session
  cookie is issued; other provisioning failures are handled as before (sk-775).
- Native OIDC sign-out sends the client id with the logout request, so the
  identity provider recognises the application even though the local session
  is already gone. Keycloak may show a logout confirmation page; the single
  sign-on session ends only after the user confirms it (sk-774).

### Upgrade notes

- No configuration changes. The post-logout redirect URI must still be
  registered on the Keycloak client.
- Session revocation is reliable once every skein-web replica runs 1.0.1:
  replicas still on 1.0.0 keep the old shared queue group during a rolling
  upgrade.

## [1.0.0] - 2026-10-23

- First public release.
