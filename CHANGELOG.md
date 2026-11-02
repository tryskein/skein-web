# Changelog

All notable changes to **skein-web** (.NET 10 BFF / API gateway).

## [Unreleased]

- Native OIDC sign-in preserves a `403 user_not_provisioned` response from
  skein-api instead of converting it to `502 sso_provisioning_failed`, including
  for unknown users when automatic provisioning is disabled. Access is denied
  without issuing a session cookie; other provisioning failures keep their
  existing error handling.

## [1.0.0] - 2026-10-23

- First public release.
