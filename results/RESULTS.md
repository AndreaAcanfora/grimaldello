# grimaldello results

Generated 2026-11-11T21:38:53.892Z.

| Library | Language | Version |
|---|---|---|
| @simplewebauthn/server | TypeScript | 14.1.0 |
| py_webauthn | Python | 3.0.1 |
| go-webauthn | Go | v0.18.2 |
| java-webauthn-server | Java | 2.10.1 |
| webauthn-rs | Rust | 0.5.5 |
| web-auth/webauthn-lib | PHP | 5.3.12 |
| webauthn4j | Java | 0.32.0.RELEASE |
| fido2-net-lib | C# | 4.3.3 |

87 cases. 🔓 accepted but must reject: **111** (of which security-relevant: **6**) · ⛔ rejected but must accept: **0** · 💥 crashes: **0** · ⚠️ undocumented exceptions: **36** · cases where libraries disagree: **36**

Legend: ✅ follows the spec · 🔓 accepts what it must reject · ⛔ rejects a valid ceremony · 💥 crash · 🟡/⚪ accepts/rejects where the spec leaves a choice · ➖ algorithm not supported · ⚠️ rejected, but by throwing an exception type the library does not document (an application catching the documented one answers 500)

Impact: **security** means an honest browser under attack can produce the input; **hardening** means only a modified client or authenticator can, affecting the attacker's own credential.

| Case | Impact | Expect | simplewebauthn | py_webauthn | go-webauthn | java-webauthn-server | webauthn-rs | web-auth | webauthn4j | fido2-net-lib |
|---|---|---|---|---|---|---|---|---|---|---|
| `reg-baseline-es256`<br>Valid registration, ES256, attestation none | hardening | accept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-baseline-eddsa`<br>Valid registration, EdDSA (Ed25519) | hardening | accept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-baseline-rs256`<br>Valid registration, RS256 | hardening | accept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-baseline-packed-self`<br>Valid registration, packed self-attestation | hardening | accept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-baseline-es256`<br>Valid authentication, ES256 | hardening | accept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-baseline-eddsa`<br>Valid authentication, EdDSA | hardening | accept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-baseline-rs256`<br>Valid authentication, RS256 | hardening | accept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-signcount-zero`<br>Authenticator that never increments the counter (both 0) | hardening | accept | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-wrong-challenge`<br>Challenge does not match | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-wrong-origin`<br>Origin from another site | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-origin-subdomain`<br>Origin is a subdomain of the RP | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-origin-trailing-slash`<br>Origin with a trailing slash | hardening | reject | ✅ | ✅ | 🔓 | ✅ | 🔓 | 🔓 | 🔓 | 🔓 |
| `reg-origin-uppercase`<br>Origin with an uppercase host | hardening | reject | ✅ | ✅ | 🔓 | ✅ | 🔓 | ✅ | 🔓 | 🔓 |
| `reg-origin-default-port`<br>Origin with the default port spelled out | hardening | reject | ✅ | ✅ | 🔓 | ✅ | 🔓 | 🔓 | 🔓 | 🔓 |
| `reg-origin-http`<br>Origin over plain http | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-origin-userinfo`<br>Origin with userinfo (https://example.com@evil.test) | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-type-get`<br>type is webauthn.get in a registration | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-dup-challenge-first`<br>clientDataJSON with two challenge members, the wrong one first | hardening | reject | 🔓 | 🔓 | 🔓 | 🔓 | ✅ | 🔓 | 🔓 | 🔓 |
| `reg-dup-challenge-last`<br>clientDataJSON with two challenge members, the wrong one last | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-dup-origin-last`<br>clientDataJSON with a second, malicious origin member | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-cross-origin-true`<br>crossOrigin: true without a topOrigin the RP allows | security | reject | 🔓 | 🔓 | ✅ | 🔓 | ✅ | ✅ | ✅ | ✅ |
| `reg-challenge-padded`<br>Challenge encoded as base64url with = padding | hardening | reject | ✅ | 🔓 | ✅ | 🔓 | 🔓 | ✅⚠️ | 🔓 | 🔓 |
| `reg-challenge-std-base64`<br>Challenge encoded as standard base64 (+ and /) | hardening | reject | ✅ | 🔓 | ✅ | 🔓 | 🔓 | ✅⚠️ | 🔓 | 🔓 |
| `reg-client-data-bom`<br>clientDataJSON starting with a UTF-8 byte order mark | hardening | either | 🟡 | 🟡 | ⚪ | 🟡 | ⚪ | ⚪⚠️ | ⚪⚠️ | ⚪ |
| `auth-wrong-challenge`<br>Challenge does not match | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-wrong-origin`<br>Origin from another site | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-type-create`<br>type is webauthn.create in an authentication | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-cross-origin-true`<br>crossOrigin: true without a topOrigin the RP allows | security | reject | ✅ | 🔓 | ✅ | 🔓 | 🔓 | ✅ | ✅ | ✅ |
| `auth-dup-challenge-last`<br>clientDataJSON with two challenge members, the wrong one last | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-wrong-rpid-hash`<br>rpIdHash of another RP ID | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-rpid-hash-parent`<br>rpIdHash of a registrable suffix (com) | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-up-clear`<br>User Present flag not set | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-uv-required-clear`<br>User verification required but UV flag not set | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-at-clear`<br>Attested credential data present but AT flag not set | hardening | reject | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅ | ✅⚠️ | ✅ |
| `reg-be-clear-bs-set`<br>Backup State set without Backup Eligible | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `reg-ed-set-no-extensions`<br>ED flag set but no extensions follow | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🔓 | ✅ |
| `reg-extensions-without-ed`<br>Extension data present but ED flag not set | hardening | reject | ✅ | ✅ | ✅ | ✅ | 🔓 | ✅ | ✅⚠️ | ✅ |
| `reg-authdata-trailing`<br>Trailing bytes after the credential public key | hardening | reject | ✅ | ✅ | ✅ | ✅ | 🔓 | ✅ | ✅⚠️ | ✅ |
| `reg-cred-id-mismatch`<br>Credential ID in authData differs from id/rawId | hardening | reject | 🔓 | 🔓 | ✅ | 🔓 | 🔓 | 🔓 | 🔓 | ✅ |
| `reg-cred-id-too-long`<br>Credential ID of 1024 bytes | hardening | reject | 🔓 | 🔓 | ✅ | 🔓 | 🔓 | ✅ | ✅ | ✅ |
| `reg-cred-id-length-overflow`<br>credentialIdLength larger than the remaining data | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅⚠️ | ✅ |
| `auth-wrong-rpid-hash`<br>rpIdHash of another RP ID | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-up-clear`<br>User Present flag not set | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-uv-required-clear`<br>User verification required but UV flag not set | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-signcount-regressed`<br>Signature counter lower than the stored one | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-signcount-equal`<br>Signature counter equal to the stored one (non-zero) | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-authdata-short`<br>authenticatorData of 36 bytes (one short) | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `auth-authdata-trailing`<br>Trailing bytes after authenticatorData | hardening | reject | ✅ | ✅ | ✅ | 🔓 | 🔓 | ✅ | ✅ | ✅ |
| `auth-be-clear-bs-set`<br>Backup State set without Backup Eligible | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cbor-attobj-trailing`<br>Trailing bytes after the attestationObject | hardening | reject | 🔓 | 🔓 | ✅ | 🔓 | ✅ | ✅ | ✅⚠️ | 🔓 |
| `cbor-attobj-dup-fmt`<br>attestationObject with fmt twice (packed, then none) | hardening | reject | ✅ | ✅ | ✅ | 🔓 | ✅ | ✅⚠️ | ✅ | ✅ |
| `cbor-attobj-dup-authdata`<br>attestationObject with two authData members | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅ |
| `cbor-attobj-indefinite`<br>attestationObject as an indefinite-length map | hardening | either | ⚪ | 🟡 | ⚪ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| `cbor-cose-dup-key`<br>COSE key with a duplicate x coordinate | hardening | reject | ✅ | ✅ | ✅ | ✅ | 🔓 | ✅⚠️ | 🔓 | ✅ |
| `cbor-cose-nonminimal-int`<br>COSE key with a non-minimal integer (kty as 2-byte uint) | hardening | either | ⚪ | ⚪ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| `cose-missing-alg`<br>COSE key without alg (3) | hardening | reject | ✅ | ✅⚠️ | ✅ | ✅⚠️ | ✅ | ✅⚠️ | ✅ | ✅ |
| `cose-alg-not-offered`<br>Credential algorithm not in pubKeyCredParams (EdDSA when only ES256 is offered) | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cose-es256-p384`<br>alg ES256 with crv P-384 | hardening | reject | 🔓 | 🔓 | 🔓 | ✅⚠️ | ✅ | 🔓 | 🔓 | ✅ |
| `cose-es256-okp`<br>alg ES256 with an OKP (Ed25519) key | hardening | reject | 🔓 | 🔓 | 🔓 | ✅ | ✅ | 🔓 | ✅ | ✅ |
| `cose-eddsa-rsa`<br>alg EdDSA with an RSA key | hardening | reject | 🔓 | 🔓 | 🔓 | ✅ | ✅ | 🔓 | 🔓 | 🔓 |
| `cose-point-not-on-curve`<br>EC2 point not on P-256 | hardening | reject | 🔓 | 🔓 | 🔓 | 🔓 | ✅ | 🔓 | 🔓 | ✅ |
| `cose-ec2-short-x`<br>EC2 x coordinate of 31 bytes | hardening | reject | 🔓 | 🔓 | 🔓 | ✅⚠️ | ✅ | 🔓 | 🔓 | ✅ |
| `cose-ed25519-small-order`<br>Ed25519 public key of small order (the identity point) | hardening | reject | 🔓 | 🔓 | 🔓 | 🔓 | 🔓 | 🔓 | 🔓 | 🔓 |
| `cose-rsa-small-exponent`<br>RSA key with public exponent 1 | hardening | reject | 🔓 | 🔓 | 🔓 | ✅⚠️ | ✅ | 🔓 | 🔓 | ✅ |
| `cose-rsa-1024`<br>RSA key with a 1024-bit modulus | hardening | either | 🟡 | 🟡 | 🟡 | 🟡 | ⚪ | 🟡 | 🟡 | 🟡 |
| `sig-wrong-data`<br>Signature over different data | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `sig-es256-high-s`<br>ECDSA signature with high S (n - s) | hardening | either | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| `sig-es256-raw`<br>ECDSA signature as raw r||s instead of DER | hardening | reject | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | 🔓 | ✅ | ✅ |
| `sig-es256-der-trailing`<br>DER signature with a trailing byte | hardening | reject | 🔓 | ✅ | ✅ | ✅⚠️ | ✅ | ✅⚠️ | ✅ | 🔓 |
| `sig-es256-der-long-length`<br>DER signature with a non-minimal (long-form) length | hardening | reject | 🔓 | ✅ | ✅ | ✅⚠️ | ✅ | ✅⚠️ | ✅ | 🔓 |
| `sig-es256-der-padded-int`<br>DER signature with a needless leading zero in r | hardening | reject | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅⚠️ | ✅ | ✅ |
| `sig-es256-zero`<br>ECDSA signature with r = s = 0 | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅ |
| `sig-es256-s-equals-n`<br>ECDSA signature with s = n | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `sig-eddsa-s-plus-l`<br>Ed25519 signature with S + L (non-canonical S) | hardening | reject | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅ | ✅ | ✅ |
| `sig-eddsa-truncated`<br>Ed25519 signature of 63 bytes | hardening | reject | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅ | ✅ | ✅ |
| `sig-rs256-leading-zero`<br>RSA signature with an extra leading zero byte | hardening | reject | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅ | ✅ | ✅ |
| `sig-empty`<br>Empty signature | security | reject | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅⚠️ | ✅ | ✅ |
| `sig-other-credential`<br>Assertion signed by a different key than the registered one | security | reject | ✅ | ✅ | ✅ | ✅⚠️ | ✅ | ✅ | ✅ | ✅ |
| `att-none-with-statement`<br>fmt none with a non-empty attStmt | hardening | reject | ✅ | ✅ | ✅ | 🔓 | 🔓 | ✅ | ✅ | ✅ |
| `att-unknown-fmt`<br>Unknown attestation format | hardening | reject | ✅ | ✅ | ✅ | 🔓 | ✅ | ✅ | ✅⚠️ | ✅ |
| `att-packed-bad-sig`<br>Packed self-attestation with an invalid signature | security | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `att-packed-alg-mismatch`<br>Packed self-attestation whose alg differs from the credential's | hardening | reject | 🔓 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `att-packed-missing-sig`<br>Packed attestation without sig | hardening | reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅⚠️ | ✅ |
| `enc-id-padded`<br>Credential id with base64url padding | hardening | either | ⚪ | ⚪ | ⚪ | 🟡 | 🟡 | ⚪⚠️ | 🟡 | 🟡 |
| `enc-type-wrong`<br>Credential type other than public-key | hardening | reject | ✅ | ✅ | ✅ | ✅ | 🔓 | ✅ | 🔓 | ✅ |
| `enc-id-rawid-mismatch`<br>id and rawId refer to different credentials | hardening | reject | ✅ | ✅ | ✅ | ✅ | 🔓 | ✅ | 🔓 | ✅ |
| `enc-auth-raw-padding`<br>authenticatorData as base64url with = padding | hardening | either | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |

## Details

### `reg-origin-trailing-slash`: Origin with a trailing slash

Impact: hardening. Spec: §7.1 step 9 + §5.8.1: origin is the serialized origin, compared exactly

- ✅ **simplewebauthn**: reject: `Unexpected response origin "https://example.com/", expected one of: https://example.com`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: Unexpected client data origin "https://example.com/", expected "https://example.com"`
- 🔓 **go-webauthn**: accept
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.RegistrationFailedException: java.lang.IllegalArgumentException: Incorrect origin, please see the RelyingParty.origins setting: https://example.com/`
- 🔓 **webauthn-rs**: accept
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- 🔓 **fido2-net-lib**: accept

### `reg-origin-uppercase`: Origin with an uppercase host

Impact: hardening. Spec: §5.8.1: browsers serialize the origin in lowercase, so this never comes from a real browser

- ✅ **simplewebauthn**: reject: `Unexpected response origin "https://EXAMPLE.com", expected one of: https://example.com`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: Unexpected client data origin "https://EXAMPLE.com", expected "https://example.com"`
- 🔓 **go-webauthn**: accept
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.RegistrationFailedException: java.lang.IllegalArgumentException: Incorrect origin, please see the RelyingParty.origins setting: https://EXAMPLE.com`
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\AuthenticatorResponseVerificationException: Invalid origin. Not in the list of allowed origins.`
- 🔓 **webauthn4j**: accept
- 🔓 **fido2-net-lib**: accept

### `reg-origin-default-port`: Origin with the default port spelled out

Impact: hardening. Spec: §5.8.1: the serialized origin omits the default port

- ✅ **simplewebauthn**: reject: `Unexpected response origin "https://example.com:443", expected one of: https://example.com`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: Unexpected client data origin "https://example.com:443", expected "https://example.com"`
- 🔓 **go-webauthn**: accept
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.RegistrationFailedException: java.lang.IllegalArgumentException: Incorrect origin, please see the RelyingParty.origins setting: https://example.com:443`
- 🔓 **webauthn-rs**: accept
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- 🔓 **fido2-net-lib**: accept

### `reg-dup-challenge-first`: clientDataJSON with two challenge members, the wrong one first

Impact: hardening. Spec: §5.8.1.2: the JSON is not in the limited verification form; parsers disagree on which duplicate wins

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- 🔓 **go-webauthn**: accept
- 🔓 **java-webauthn-server**: accept
- ✅ **webauthn-rs**: reject: `ParseJSONFailure(Error("duplicate field 'challenge'", line: 1, column: 95))`
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- 🔓 **fido2-net-lib**: accept

### `reg-cross-origin-true`: crossOrigin: true without a topOrigin the RP allows

Impact: security. Spec: §7.1 steps 10–11 (Level 3): the RP did not opt in to cross-origin iframes

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- ✅ **go-webauthn**: reject: `verification_error: Error validating cross origin flag The cross origin flag is invalid due to the configuration.`
- 🔓 **java-webauthn-server**: accept
- ✅ **webauthn-rs**: reject: `CredentialCrossOrigin`
- ✅ **web-auth**: reject: `Webauthn\Exception\AuthenticatorResponseVerificationException: A cross-origin response was received but no TopOriginValidator is configured. Configure one via CeremonyStepManagerFactory::enableTopOrig`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadTopOriginException: The collectedClientData topOrigin 'https://evil.test' doesn't match any of the preconfigured server topOrigin.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Authenticator response was created in a cross-origin context, but the Relying Party does not allow cross-origin requests`

### `reg-challenge-padded`: Challenge encoded as base64url with = padding

Impact: hardening. Spec: §5.8.1: challenge is base64url without padding; the decoded bytes still match

- ✅ **simplewebauthn**: reject: `Unexpected registration response challenge "Rww0pt4WFHzpTH1KGg8omzs2KgGdMJzDxs1QvAJQKyk=", expected "Rww0pt4WFHzpTH1KGg8omzs2KgGdMJzDxs1QvAJQKyk"`
- 🔓 **py_webauthn**: accept
- ✅ **go-webauthn**: reject: `verification_error: Error validating challenge Expected b Value: "Rww0pt4WFHzpTH1KGg8omzs2KgGdMJzDxs1QvAJQKyk"
Received b: "Rww0pt4WFHzpTH1KGg8omzs2KgGdMJzDxs1QvAJQKyk="
`
- 🔓 **java-webauthn-server**: accept
- 🔓 **webauthn-rs**: accept
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: decodeNoPadding() doesn't tolerate padding`
- 🔓 **webauthn4j**: accept
- 🔓 **fido2-net-lib**: accept

### `reg-challenge-std-base64`: Challenge encoded as standard base64 (+ and /)

Impact: hardening. Spec: §5.8.1: challenge is base64url

- ✅ **simplewebauthn**: reject: `Unexpected registration response challenge "t4ffl47H5E1V6K49gJApltPypFiuJ5j96pCRuTnNq5U=", expected "t4ffl47H5E1V6K49gJApltPypFiuJ5j96pCRuTnNq5U"`
- 🔓 **py_webauthn**: accept
- ✅ **go-webauthn**: reject: `verification_error: Error validating challenge Expected b Value: "t4ffl47H5E1V6K49gJApltPypFiuJ5j96pCRuTnNq5U"
Received b: "t4ffl47H5E1V6K49gJApltPypFiuJ5j96pCRuTnNq5U="
`
- 🔓 **java-webauthn-server**: accept
- 🔓 **webauthn-rs**: accept
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: decodeNoPadding() doesn't tolerate padding`
- 🔓 **webauthn4j**: accept
- 🔓 **fido2-net-lib**: accept

### `reg-client-data-bom`: clientDataJSON starting with a UTF-8 byte order mark

Impact: hardening. Spec: §5.8.1.2: browsers never emit a BOM; JSON parsers differ

- 🟡 **simplewebauthn**: accept
- 🟡 **py_webauthn**: accept
- ⚪ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- 🟡 **java-webauthn-server**: accept
- ⚪ **webauthn-rs**: reject: `ParseJSONFailure(Error("expected value", line: 1, column: 1))`
- ⚪⚠️ **web-auth**: reject: `JsonException: Syntax error`
- ⚪⚠️ **webauthn4j**: reject: `tools.jackson.core.exc.StreamReadException: Unexpected character ('﻿' (code 65279 / 0xfeff)): expected a valid value (JSON String, Number, Array, Object or token 'null', 'true' or 'false')
 at [Source`
- ⚪ **fido2-net-lib**: reject: `Fido2VerificationException: Malformed clientDataJson`

### `auth-cross-origin-true`: crossOrigin: true without a topOrigin the RP allows

Impact: security. Spec: §7.2 steps 13–14 (Level 3): the RP did not opt in to cross-origin iframes

- ✅ **simplewebauthn**: reject: `Detected cross-origin authentication response from top origin of "https://evil.test", but a value for 'expectedTopOrigin' was not specified when calling 'verifyAuthenticationResponse()'`
- 🔓 **py_webauthn**: accept
- ✅ **go-webauthn**: reject: `verification_error: Error validating cross origin flag The cross origin flag is invalid due to the configuration.`
- 🔓 **java-webauthn-server**: accept
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\AuthenticatorResponseVerificationException: A cross-origin response was received but no TopOriginValidator is configured. Configure one via CeremonyStepManagerFactory::enableTopOrig`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadTopOriginException: The collectedClientData topOrigin 'https://evil.test' doesn't match any of the preconfigured server topOrigin.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Authenticator response was created in a cross-origin context, but the Relying Party does not allow cross-origin requests`

### `reg-at-clear`: Attested credential data present but AT flag not set

Impact: hardening. Spec: §6.1: authData is malformed

- ✅ **simplewebauthn**: reject: `Leftover bytes detected while parsing authenticator data`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: attestationObject was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- ✅⚠️ **java-webauthn-server**: reject: `java.util.NoSuchElementException: No value present`
- ✅ **webauthn-rs**: reject: `MissingAttestationCredentialData`
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Invalid authentication data. Presence of extra bytes.`
- ✅⚠️ **webauthn4j**: reject: `tools.jackson.databind.DatabindException: provided data does not have proper byte layout
 at [Source: (byte[])[194 bytes]; byte offset: #194] (through reference chain: com.webauthn4j.data.attestation.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Leftover bytes decoding AuthenticatorData`

### `reg-ed-set-no-extensions`: ED flag set but no extensions follow

Impact: hardening. Spec: §6.1: authData is malformed

- ✅ **simplewebauthn**: reject: `No data`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: attestationObject was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- ✅ **java-webauthn-server**: reject: `com.fasterxml.jackson.databind.exc.ValueInstantiationException: Cannot construct instance of 'com.yubico.webauthn.data.AuthenticatorAttestationResponse', problem: Flags indicate there should be extens`
- ✅ **webauthn-rs**: reject: `ParseNOMFailure`
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Out of range. Expected: 1, read: 0.`
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Malformed AttestationObject`

### `reg-extensions-without-ed`: Extension data present but ED flag not set

Impact: hardening. Spec: §6.1: trailing data after the credential public key

- ✅ **simplewebauthn**: reject: `Leftover bytes detected while parsing authenticator data`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: attestationObject was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- ✅ **java-webauthn-server**: reject: `com.fasterxml.jackson.databind.exc.ValueInstantiationException: Cannot construct instance of 'com.yubico.webauthn.data.AuthenticatorAttestationResponse', problem: Flags indicate no extension data, but`
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Invalid authentication data. Presence of extra bytes.`
- ✅⚠️ **webauthn4j**: reject: `tools.jackson.databind.DatabindException: provided data does not have proper byte layout
 at [Source: (byte[])[208 bytes]; byte offset: #208] (through reference chain: com.webauthn4j.data.attestation.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Leftover bytes decoding AuthenticatorData`

### `reg-authdata-trailing`: Trailing bytes after the credential public key

Impact: hardening. Spec: §6.1: authData is malformed

- ✅ **simplewebauthn**: reject: `Leftover bytes detected while parsing authenticator data`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: attestationObject was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- ✅ **java-webauthn-server**: reject: `com.fasterxml.jackson.databind.exc.ValueInstantiationException: Cannot construct instance of 'com.yubico.webauthn.data.AuthenticatorAttestationResponse', problem: Flags indicate no extension data, but`
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Invalid authentication data. Presence of extra bytes.`
- ✅⚠️ **webauthn4j**: reject: `tools.jackson.databind.DatabindException: provided data does not have proper byte layout
 at [Source: (byte[])[198 bytes]; byte offset: #198] (through reference chain: com.webauthn4j.data.attestation.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Leftover bytes decoding AuthenticatorData`

### `reg-cred-id-mismatch`: Credential ID in authData differs from id/rawId

Impact: hardening. Spec: §7.1: the RP stores the credential ID from authData, so a mismatch lets a client register one ID and log in with another

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- ✅ **go-webauthn**: reject: `verification_error: Error validating the attested credential id The credential id reported by the client does not match the credential id in the attested credential data`
- 🔓 **java-webauthn-server**: accept
- 🔓 **webauthn-rs**: accept
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: AttestationResponse rawId does not match the credentialId in the attested credential data`

### `reg-cred-id-too-long`: Credential ID of 1024 bytes

Impact: hardening. Spec: §7.1 step 28: credentialId must be at most 1023 bytes

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- 🔓 **java-webauthn-server**: accept
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\AuthenticatorResponseVerificationException: Credential ID too long.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.CredentialIdTooLongException: credentialId exceeds maxCredentialIdSize(1023 bytes)`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: CredentialId too many bytes`

### `reg-cred-id-length-overflow`: credentialIdLength larger than the remaining data

Impact: hardening. Spec: §6.5.1: authData is truncated

- ✅ **simplewebauthn**: reject: `No data`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: attestationObject was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- ✅ **java-webauthn-server**: reject: `com.fasterxml.jackson.databind.exc.ValueInstantiationException: Cannot construct instance of 'com.yubico.webauthn.data.AuthenticatorAttestationResponse', problem: Expected credential ID of length 6555`
- ✅ **webauthn-rs**: reject: `ParseNOMFailure`
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Out of range. Expected: 65535, read: 109.`
- ✅⚠️ **webauthn4j**: reject: `tools.jackson.databind.DatabindException: provided data does not have proper byte layout
 at [Source: (byte[])[194 bytes]; byte offset: #194] (through reference chain: com.webauthn4j.data.attestation.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: CredentialId too many bytes`

### `auth-authdata-trailing`: Trailing bytes after authenticatorData

Impact: hardening. Spec: §6.1: authData is malformed (and covered by the signature)

- ✅ **simplewebauthn**: reject: `Leftover bytes detected while parsing authenticator data`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: authenticatorData was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error unmarshalling auth data `
- 🔓 **java-webauthn-server**: accept
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Invalid authentication data. Presence of extra bytes.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.converter.exception.DataConversionException: provided data does not have proper byte layout`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Leftover bytes decoding AuthenticatorData`

### `cbor-attobj-trailing`: Trailing bytes after the attestationObject

Impact: hardening. Spec: RFC 8949 §5.3: not well-formed as a single data item

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- 🔓 **java-webauthn-server**: accept
- ✅ **webauthn-rs**: reject: `ParseCBORFailure(ErrorImpl { code: TrailingData, offset: 195 })`
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Invalid attestation object. Presence of extra bytes.`
- ✅⚠️ **webauthn4j**: reject: `tools.jackson.databind.exc.MismatchedInputException: Trailing token ('JsonToken.VALUE_NUMBER_INT') found after value (bound as 'com.webauthn4j.data.attestation.AttestationObject'): not allowed as per `
- 🔓 **fido2-net-lib**: accept

### `cbor-attobj-dup-fmt`: attestationObject with fmt twice (packed, then none)

Impact: hardening. Spec: §6.5.4 + CTAP2 canonical CBOR: duplicate keys are invalid

- ✅ **simplewebauthn**: reject: `Map is not supported or well formed`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: attestationObject was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- 🔓 **java-webauthn-server**: accept
- ✅ **webauthn-rs**: reject: `ParseCBORFailure(ErrorImpl { code: Message("duplicate field 'fmt'"), offset: 0 })`
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: Invalid key. The key "fmt" is defined more than once in the map.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadAttestationStatementException: Unknown property is set to the none attestation statement.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Invalid AttestationObject CBOR data`

### `cbor-attobj-dup-authdata`: attestationObject with two authData members

Impact: hardening. Spec: RFC 8949 §5.6: duplicate keys

- ✅ **simplewebauthn**: reject: `Map is not supported or well formed`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: attestationObject was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.RegistrationFailedException: java.lang.IllegalArgumentException: Wrong RP ID hash.`
- ✅ **webauthn-rs**: reject: `ParseCBORFailure(ErrorImpl { code: Message("duplicate field 'authData'"), offset: 0 })`
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: Invalid key. The key "authData" is defined more than once in the map.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadRpIdException: rpIdHash doesn't match the hash of preconfigured rpId. Expected: A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947, Actual: 9834F30F8`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Invalid AttestationObject CBOR data`

### `cbor-cose-dup-key`: COSE key with a duplicate x coordinate

Impact: hardening. Spec: RFC 9052 §7: duplicate labels make the key invalid

- ✅ **simplewebauthn**: reject: `Map is not supported or well formed`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: attestationObject was malformed. See __cause__ for more info`
- ✅ **go-webauthn**: reject: `parse_error: Error parsing attestation response `
- ✅ **java-webauthn-server**: reject: `com.fasterxml.jackson.databind.exc.ValueInstantiationException: Cannot construct instance of 'com.yubico.webauthn.data.AuthenticatorAttestationResponse', problem: Duplicate key already exists
 at [Sou`
- 🔓 **webauthn-rs**: accept
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: Invalid key. The key "-2" is defined more than once in the map.`
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Malformed AttestationObject`

### `cose-missing-alg`: COSE key without alg (3)

Impact: hardening. Spec: §7.1 step 20 (Level 3): alg must be present and match pubKeyCredParams

- ✅ **simplewebauthn**: reject: `Credential public key was missing numeric alg`
- ✅⚠️ **py_webauthn**: reject: `KeyError: <COSEKey.ALG: 3>`
- ✅ **go-webauthn**: reject: `invalid_attestation: Invalid attestation format Credential public key algorithm not supported`
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.NullPointerException: Cannot invoke "com.upokecenter.cbor.CBORObject.AsInt32()" because the return value of "com.upokecenter.cbor.CBORObject.get(com.upokecenter.cbor.CBORObject)" is null`
- ✅ **webauthn-rs**: reject: `COSEKeyInvalidCBORValue`
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: The key has no data at index 3`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.ConstraintViolationException: coseKey must not be null`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Malformed AttestationObject`

### `cose-es256-p384`: alg ES256 with crv P-384

Impact: hardening. Spec: RFC 9053 §2.1: ES256 is ECDSA with P-256

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- 🔓 **go-webauthn**: accept
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to parse credential public key`
- ✅ **webauthn-rs**: reject: `COSEKeyECDSAXYInvalid`
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Algorithm ES256 cannot be used with an EC2 key on curve P384`

### `cose-es256-okp`: alg ES256 with an OKP (Ed25519) key

Impact: hardening. Spec: RFC 9053: algorithm and key type do not match

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- 🔓 **go-webauthn**: accept
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.RegistrationFailedException: java.lang.IllegalArgumentException: COSE key type (kty: 1) does not match algorithm (alg: ES256, expected kty: 2)`
- ✅ **webauthn-rs**: reject: `COSEKeyInvalidType`
- 🔓 **web-auth**: accept
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.ConstraintViolationException: algorithm must be EdDSA, Ed25519, or Ed448 if present`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Algorithm ES256 cannot be used with an OKP key`

### `cose-eddsa-rsa`: alg EdDSA with an RSA key

Impact: hardening. Spec: RFC 9053: algorithm and key type do not match

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- 🔓 **go-webauthn**: accept
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.RegistrationFailedException: java.lang.IllegalArgumentException: COSE key type (kty: 3) does not match algorithm (alg: EdDSA, expected kty: 1)`
- ✅ **webauthn-rs**: reject: `COSEKeyInvalidType`
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- 🔓 **fido2-net-lib**: accept

### `cose-point-not-on-curve`: EC2 point not on P-256

Impact: hardening. Spec: SEC 1 §3.2.2: public key validation

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- 🔓 **go-webauthn**: accept
- 🔓 **java-webauthn-server**: accept
- ✅ **webauthn-rs**: reject: `OpenSSLError(ErrorStack([Error { code: 134217835, library: "elliptic curve routines", function: "EC_POINT_set_affine_coordinates", reason: "point is not on curve", file: "crypto/ec/ec_lib.c", line: 87`
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Malformed AttestationObject`

### `cose-ec2-short-x`: EC2 x coordinate of 31 bytes

Impact: hardening. Spec: RFC 9053 §7.1.1: x is the curve size, leading zeros included

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- 🔓 **go-webauthn**: accept
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to parse credential public key`
- ✅ **webauthn-rs**: reject: `COSEKeyECDSAXYInvalid`
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: EC2 credential public key x-coordinate must be 32 bytes for curve P256, got 31`

### `cose-ed25519-small-order`: Ed25519 public key of small order (the identity point)

Impact: hardening. Spec: RFC 8032 §5.1.7 / ZIP-215: a small-order key lets any signature with S=0 verify

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- 🔓 **go-webauthn**: accept
- 🔓 **java-webauthn-server**: accept
- 🔓 **webauthn-rs**: accept
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- 🔓 **fido2-net-lib**: accept

### `cose-rsa-small-exponent`: RSA key with public exponent 1

Impact: hardening. Spec: e=1 makes every 'signature' equal to the padded message

- 🔓 **simplewebauthn**: accept
- 🔓 **py_webauthn**: accept
- 🔓 **go-webauthn**: accept
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to parse credential public key`
- ✅ **webauthn-rs**: reject: `COSEKeyRSANEInvalid`
- 🔓 **web-auth**: accept
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Malformed AttestationObject`

### `sig-es256-raw`: ECDSA signature as raw r||s instead of DER

Impact: hardening. Spec: §6.5.6: ES256 signatures are ASN.1 DER Ecdsa-Sig-Value

- ✅ **simplewebauthn**: reject: `End of input reached before message was fully decoded (inconsistent offset and length values)`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: Signature invalid or not provided `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: Sun EC public key, 256 bits
  public x coord: 1`
- ✅ **webauthn-rs**: reject: `OpenSSLError(ErrorStack([]))`
- 🔓 **web-auth**: accept
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Signature does not match`

### `sig-es256-der-trailing`: DER signature with a trailing byte

Impact: hardening. Spec: X.690: DER has one encoding; trailing data is not DER

- 🔓 **simplewebauthn**: accept
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: Signature invalid or not provided `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: Sun EC public key, 256 bits
  public x coord: 1`
- ✅ **webauthn-rs**: reject: `OpenSSLError(ErrorStack([]))`
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: Invalid data. Sequence length mismatch.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- 🔓 **fido2-net-lib**: accept

### `sig-es256-der-long-length`: DER signature with a non-minimal (long-form) length

Impact: hardening. Spec: X.690 §10.1: DER requires the shortest length form

- 🔓 **simplewebauthn**: accept
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: Signature invalid or not provided `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: Sun EC public key, 256 bits
  public x coord: 1`
- ✅ **webauthn-rs**: reject: `OpenSSLError(ErrorStack([]))`
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: Invalid data. Non-minimal length encoding.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- 🔓 **fido2-net-lib**: accept

### `sig-es256-der-padded-int`: DER signature with a needless leading zero in r

Impact: hardening. Spec: X.690 §8.3.2: integers use the minimum number of bytes

- ✅ **simplewebauthn**: reject: `Invalid signature component length 33, expected 32`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: Signature invalid or not provided `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: Sun EC public key, 256 bits
  public x coord: 1`
- ✅ **webauthn-rs**: reject: `OpenSSLError(ErrorStack([]))`
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: Invalid data. Non-minimal integer.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Signature does not match`

### `sig-es256-zero`: ECDSA signature with r = s = 0

Impact: security. Spec: FIPS 186-5 §6.4.2: r and s must be in [1, n-1]

- ✅ **simplewebauthn**: reject: `verified: false`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: <nil> `
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.AssertionFailedException: java.lang.IllegalArgumentException: Invalid assertion signature.`
- ✅ **webauthn-rs**: reject: `AuthenticationFailure`
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: Invalid signature. R and S must be positive integers.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Signature does not match`

### `sig-eddsa-s-plus-l`: Ed25519 signature with S + L (non-canonical S)

Impact: hardening. Spec: RFC 8032 §5.1.7: S must be < L

- ✅ **simplewebauthn**: reject: `verified: false`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: <nil> `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: algorithm = Ed25519, unparsed keybits = 
0000: `
- ✅ **webauthn-rs**: reject: `AuthenticationFailure`
- ✅ **web-auth**: reject: `Webauthn\Exception\AuthenticatorResponseVerificationException: Invalid signature.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Signature does not match`

### `sig-eddsa-truncated`: Ed25519 signature of 63 bytes

Impact: hardening. Spec: RFC 8032: signatures are 64 bytes

- ✅ **simplewebauthn**: reject: `verified: false`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: <nil> `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: algorithm = Ed25519, unparsed keybits = 
0000: `
- ✅ **webauthn-rs**: reject: `AuthenticationFailure`
- ✅ **web-auth**: reject: `Webauthn\Exception\AuthenticatorResponseVerificationException: Invalid signature.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Signature does not match`

### `sig-rs256-leading-zero`: RSA signature with an extra leading zero byte

Impact: hardening. Spec: RFC 8017 §8.2.2: the signature must be exactly k bytes

- ✅ **simplewebauthn**: reject: `verified: false`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: crypto/rsa: verification error `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: Sun RSA public key, 2048 bits
  params: null
  `
- ✅ **webauthn-rs**: reject: `AuthenticationFailure`
- ✅ **web-auth**: reject: `Webauthn\Exception\AuthenticatorResponseVerificationException: Invalid signature.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Signature does not match`

### `sig-empty`: Empty signature

Impact: security. Spec: §7.2 step 21

- ✅ **simplewebauthn**: reject: `Input buffer has zero length`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: Signature invalid or not provided `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: Sun EC public key, 256 bits
  public x coord: 1`
- ✅ **webauthn-rs**: reject: `AuthenticationFailure`
- ✅⚠️ **web-auth**: reject: `InvalidArgumentException: Invalid data. Should start with a sequence.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Signature does not match`

### `sig-other-credential`: Assertion signed by a different key than the registered one

Impact: security. Spec: §7.2 step 21: verify with the stored credential public key

- ✅ **simplewebauthn**: reject: `Too big integer`
- ✅ **py_webauthn**: reject: `InvalidAuthenticationResponse: Could not verify authentication signature`
- ✅ **go-webauthn**: reject: `invalid_signature: Error validating the assertion signature: Signature invalid or not provided `
- ✅⚠️ **java-webauthn-server**: reject: `java.lang.RuntimeException: Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: Sun EC public key, 256 bits
  public x coord: 1`
- ✅ **webauthn-rs**: reject: `OpenSSLError(ErrorStack([]))`
- ✅ **web-auth**: reject: `Webauthn\Exception\AuthenticatorResponseVerificationException: Invalid signature.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadSignatureException: Assertion signature is not valid.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Signature does not match`

### `att-none-with-statement`: fmt none with a non-empty attStmt

Impact: hardening. Spec: §8.7: the none attStmt is an empty map

- ✅ **simplewebauthn**: reject: `None attestation had unexpected attestation statement`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: None attestation had unexpected attestation statement`
- ✅ **go-webauthn**: reject: `invalid_attestation: Invalid attestation format Attestation format none with attestation present`
- 🔓 **java-webauthn-server**: accept
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\AttestationStatementLoadingException: Invalid attestation object`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadAttestationStatementException: Unknown property is set to the none attestation statement.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Attestation format none should have no attestation statement`

### `att-unknown-fmt`: Unknown attestation format

Impact: hardening. Spec: §7.1 step 21: fmt must be a supported format

- ✅ **simplewebauthn**: reject: `Unsupported Attestation Format: grimaldello`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: Unsupported attestation type "grimaldello"`
- ✅ **go-webauthn**: reject: `invalid_attestation: Invalid attestation format Attestation format grimaldello is unsupported`
- 🔓 **java-webauthn-server**: accept
- ✅ **webauthn-rs**: reject: `AttestationNotSupported`
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: The attestation statement format "grimaldello" is not supported.`
- ✅⚠️ **webauthn4j**: reject: `tools.jackson.databind.exc.InvalidTypeIdException: Could not resolve type id 'grimaldello' as a subtype of 'com.webauthn4j.data.attestation.statement.AttestationStatement': known type ids = [android-k`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Unknown attestation type. Was 'grimaldello'`

### `att-packed-alg-mismatch`: Packed self-attestation whose alg differs from the credential's

Impact: hardening. Spec: §8.2: in self attestation, alg must match the credential public key's alg

- 🔓 **simplewebauthn**: accept
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: Credential public key alg -7 did not equal attestation statement alg -257`
- ✅ **go-webauthn**: reject: `invalid_attestation: Public key algorithm does not equal att statement algorithm `
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.RegistrationFailedException: java.lang.IllegalArgumentException: Key algorithm and signature algorithm must be equal, was: Key: ES256, Sig: RS256`
- ✅ **webauthn-rs**: reject: `AttestationStatementAlgMismatch`
- ✅ **web-auth**: reject: `Webauthn\Exception\AttestationStatementVerificationException: The algorithm of the attestation statement and the key are not identical.`
- ✅ **webauthn4j**: reject: `com.webauthn4j.verifier.exception.BadAlgorithmException: 'alg' in attestation statement doesn't match the algorithm of the coseKey in authenticatorData.`
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Algorithm mismatch between credential public key and authenticator data in self attestation statement`

### `att-packed-missing-sig`: Packed attestation without sig

Impact: hardening. Spec: §8.2: attStmt must contain sig

- ✅ **simplewebauthn**: reject: `No attestation signature provided in attestation statement (Packed)`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: Attestation statement was missing signature (Packed)`
- ✅ **go-webauthn**: reject: `invalid_attestation: Error retrieving sig value packed`
- ✅ **java-webauthn-server**: reject: `com.yubico.webauthn.exception.RegistrationFailedException: java.lang.IllegalArgumentException: attStmt.sig must be set to a binary value.`
- ✅ **webauthn-rs**: reject: `AttestationStatementSigMissing`
- ✅ **web-auth**: reject: `Webauthn\Exception\AttestationStatementLoadingException: The attestation statement value "sig" is missing.`
- ✅⚠️ **webauthn4j**: reject: `tools.jackson.databind.exc.ValueInstantiationException: Cannot construct instance of 'com.webauthn4j.data.attestation.statement.PackedAttestationStatement', problem: sig must not be null
 at [Source: `
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: Invalid packed attestation signature`

### `enc-id-padded`: Credential id with base64url padding

Impact: hardening. Spec: §5.1: id is base64url without padding; the bytes still match rawId

- ⚪ **simplewebauthn**: reject: `Credential ID was not base64url-encoded`
- ⚪ **py_webauthn**: reject: `InvalidRegistrationResponse: id and raw_id were not equivalent`
- ⚪ **go-webauthn**: reject: `invalid_request: Parse error for Registration ID not base64.RawURLEncoded`
- 🟡 **java-webauthn-server**: accept
- 🟡 **webauthn-rs**: accept
- ⚪⚠️ **web-auth**: reject: `InvalidArgumentException: decodeNoPadding() doesn't tolerate padding`
- 🟡 **webauthn4j**: accept
- 🟡 **fido2-net-lib**: accept

### `enc-type-wrong`: Credential type other than public-key

Impact: hardening. Spec: §5.1: type is "public-key"

- ✅ **simplewebauthn**: reject: `Unexpected credential type password, expected "public-key"`
- ✅ **py_webauthn**: reject: `InvalidJSONStructure: Credential had unexpected type`
- ✅ **go-webauthn**: reject: `invalid_request: Parse error for Registration Type not public-key`
- ✅ **java-webauthn-server**: reject: `com.fasterxml.jackson.databind.exc.ValueInstantiationException: Cannot construct instance of 'com.yubico.webauthn.data.PublicKeyCredentialType', problem: Unknown PublicKeyCredentialType value: passwor`
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Invalid parameter "type". Shall be "public-key".`
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `JsonException: The JSON value could not be converted to System.Nullable'1[Fido2NetLib.Objects.PublicKeyCredentialType]. Path: $.type | LineNumber: 0 | BytePositionInLine: 123.`

### `enc-id-rawid-mismatch`: id and rawId refer to different credentials

Impact: hardening. Spec: §5.1: id is the base64url encoding of rawId

- ✅ **simplewebauthn**: reject: `Credential ID was not base64url-encoded`
- ✅ **py_webauthn**: reject: `InvalidRegistrationResponse: id and raw_id were not equivalent`
- ✅ **go-webauthn**: reject: `invalid_request: Parse error for Registration ID does not match rawId`
- ✅ **java-webauthn-server**: reject: `com.fasterxml.jackson.databind.exc.ValueInstantiationException: Cannot construct instance of 'com.yubico.webauthn.data.PublicKeyCredential', problem: "id" and "rawId" are not equal: ByteArray(7796b5d4`
- 🔓 **webauthn-rs**: accept
- ✅ **web-auth**: reject: `Webauthn\Exception\InvalidDataException: Invalid ID`
- 🔓 **webauthn4j**: accept
- ✅ **fido2-net-lib**: reject: `Fido2VerificationException: AttestationResponse Id is not valid base64url, or does not match RawId`
