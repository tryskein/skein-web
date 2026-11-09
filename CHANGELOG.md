# Changelog

All notable changes to **skein-web** (.NET 10 BFF / API gateway).

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
