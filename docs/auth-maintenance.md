# Authentication maintenance

This fork starts from dchristl/macless-haystack. Changes are reviewed individually;
an upstream commit or a passing mocked test is not evidence of successful Apple
authentication.

## Evidence as of 2026-09-08

- SRP initialization and password proof reached `trustedDeviceSecondaryAuth`.
- The Gitee SMS resend URL with a trailing slash returned HTTP 405.
- Replacing it with the upstream idmsa URL returned HTTP 401 in our GSA context.
- Trusted-device requests returned HTTP 401, including with a Session spanning SRP.
- These results do NOT prove that Apple disabled GSA globally or that all 401s
  have the same cause. Complete cookie reuse did not resolve this case.
- No successful `auth.json` or ready report endpoint has been verified.

## Request-context corrections under live validation

The first fork patch omitted the trusted-device `Accept` and `Content-Type`
headers present in both AltSign and FindMy.py. It also mixed the Anisette
client description with a hardcoded GSA description, and used a case-sensitive
dictionary for HTTP header merging. A local diagnostic reproduced all three
differences without submitting credentials.

Current changes use one case-insensitive identity mapping, the same client
description for GSA and 2FA, and explicit plist headers for trusted devices.
Client-info is an HTTP header rather than an additional CPD field, matching
FindMy.py. Validation checks the Apple plist error code as well as HTTP status.
Authentication response bodies and header values are no longer logged here.

Offline checks:

```sh
python -m unittest discover -s tests -p 'test_auth_context.py'
```

These tests use fake responses and verify request construction, negative
responses, and no blind retries. The deployment remains experimental until a
real login creates the report token and the report service responds.

## Sources considered

- https://github.com/dchristl/macless-haystack
- https://github.com/malmeloo/FindMy.py/blob/main/findmy/reports/account.py
- https://github.com/malmeloo/FindMy.py/blob/main/findmy/reports/anisette.py
- https://github.com/rileytestut/AltSign/blob/master/AltSign/Apple%20API/ALTAppleAPI%2BAuthentication.m
- https://github.com/MatthewKuKanich/FindMyFlipper/pull/144

The device-identity PR is a hypothesis with useful implementation ideas, not a
proof of the cause of our 401. FindMy.py uses a different identity construction,
so wholesale copying either implementation is inappropriate without validation.

## Deployment and remaining limitations

The existing container uses a read-only bind mount of the fork's authentication
module and skips its original startup git pull. It is still based on the Gitee
image, not a complete reproducible image built from this fork.

TLS verification remains inherited from upstream. A local check validated the
setup.icloud.com certificate but failed to validate gsa.apple.com with the
current bundle. A verified Apple CA/trust-store solution is still needed;
silencing TLS warnings is not a certificate fix.

Do not put passwords, verification codes, auth.json, Anisette provisioning data,
or raw authentication responses in this repository. Changes to transport should
be validated with a controlled interactive attempt, not repeated automatic login.
