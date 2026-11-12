# grimaldello

**A differential test suite for passkey (WebAuthn) server libraries.** It sends the same registration and login ceremonies, each with one deliberate defect, to nine relying-party libraries in eight languages, and reports where they disagree. When two libraries give different answers to the same bytes, at least one of them is not following the specification.

*Grimaldello* is Italian for “lock pick”.

**[See the results →](https://andreaacanfora.github.io/grimaldello/)**

| Library | Language |
|---|---|
| [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn) | TypeScript |
| [py_webauthn](https://github.com/duo-labs/py_webauthn) | Python |
| [go-webauthn](https://github.com/go-webauthn/webauthn) | Go |
| [java-webauthn-server](https://github.com/Yubico/java-webauthn-server) | Java |
| [webauthn-rs](https://github.com/kanidm/webauthn-rs) | Rust |
| [web-auth/webauthn-lib](https://github.com/web-auth/webauthn-framework) | PHP |
| [webauthn4j](https://github.com/webauthn4j/webauthn4j) | Java |
| [fido2-net-lib](https://github.com/passwordless-lib/fido2-net-lib) | C# |
| [webauthn-ruby](https://github.com/cedarcode/webauthn-ruby) | Ruby |

## What it tests

87 cases, grouped by where the defect is:

- **clientDataJSON**: wrong challenge, origin or type; origins that differ only in spelling (trailing slash, uppercase host, explicit default port, userinfo); duplicate JSON members; `crossOrigin` and `topOrigin`; challenges in padded or standard base64.
- **authenticatorData**: wrong RP ID hash, missing user presence or verification, inconsistent flags (BS without BE, ED without extensions), trailing bytes, credential IDs that are too long or differ from `rawId`, counters that go backwards.
- **CBOR**: trailing data, duplicate map keys, indefinite lengths, non-minimal integers.
- **COSE keys**: missing `alg`, algorithm and key type that do not match, points not on the curve, short coordinates, a small-order Ed25519 key, RSA with `e = 1`.
- **Signatures**: high-S and raw ECDSA, DER that is not DER (trailing bytes, long-form lengths, padded integers), `r = s = 0`, `s = n`, non-canonical Ed25519 `S`, wrong lengths, signatures by another key.
- **Attestation**: `none` with a statement, unknown formats, broken packed self-attestation.
- **Baselines**: valid ES256, EdDSA and RS256 ceremonies that every library must accept. If one fails, the run fails, because the harness is wrong, not the library.

Each case records what the WebAuthn Level 3 specification (or the RFC it points to) says a relying party must do, and an **impact**:

- **security**: an honest browser can produce this input while under attack (a phishing page, a replayed response, a ceremony without a user gesture). Accepting it weakens what WebAuthn is there to protect.
- **hardening**: only a modified client or authenticator can produce it, or the check is defence in depth. A library that accepts it is more permissive than the specification, which is a difference, not a vulnerability: excessive strictness can break real clients too. These cases are still useful where several components parse the same data.

The vectors are deterministic (fixed test keys, RFC 6979 ECDSA) and committed in [`vectors/cases.jsonl`](vectors/cases.jsonl), so you can feed them to any other library.

## Results so far

The [results page](https://andreaacanfora.github.io/grimaldello/) is rebuilt every week. Each adapter pins its library version, and Dependabot opens a pull request when a new release comes out, so the CI run shows exactly what changed. As of the first run (November 2026, versions on the page):

- No library accepted a wrong challenge, origin, RP ID, ceremony type, missing user presence or a bad signature. The core checks hold everywhere.
- The libraries differ on how strictly they parse: trailing bytes after authenticatorData or after the attestation object, duplicate CBOR keys, non-DER ECDSA signatures, origins that differ only in spelling, credential IDs longer than 1023 bytes. These are differences in strictness, not vulnerabilities.
- Almost no library validates the credential public key at registration (points off the curve, mismatched algorithm and key type, RSA with `e = 1`). The key belongs to the attacker's own credential, so this is hardening.
- `crossOrigin`/`topOrigin` (Level 3) are handled differently in every library. The webauthn-rs maintainers explained why checking them is defence in depth at best: the page must allow being framed, older clients never send these fields, and `topOrigin` does not show every origin in a chain of nested iframes. These cases are classified as hardening.
- java-webauthn-server and web-auth/webauthn-lib throw an undocumented exception type (`RuntimeException`, `InvalidArgumentException`) for malformed assertion signatures, which anyone can send; an application that only catches the documented exception answers 500 instead of 401 ([java-webauthn-server#234](https://github.com/Yubico/java-webauthn-server/issues/234)).

## Disclosure

Findings that may have a security impact are reported privately to the maintainers, and the cases stay out of this repository until a fix is released or the maintainers agree to publish.

This was not followed for the first version: the `crossOrigin` cases were published, labelled as security issues, before the webauthn-rs maintainers were contacted. After their review they are classified as hardening, as explained above. The first webauthn-rs adapter also used the lower-level `webauthn-rs-core` crate, version 0.5.5; it now uses the public `webauthn-rs` passkey API, current release.

## Run it

You need Node.js 22.18+, plus the toolchain of each library you want to test (Python 3.10+, Go, Java 17+ with Maven, Rust, PHP 8.2+ with Composer, .NET 10, Ruby 3.2+). Locally, adapters whose toolchain is missing are skipped; in CI every adapter must run.

```console
npm ci
node src/cli.ts build              # build every adapter, or name some
node src/cli.ts run                # writes results/RESULTS.md and results/results.json
node src/cli.ts run py_webauthn    # just one
```

`npm test` checks the generator itself, including verifying the baseline signatures with `node:crypto`, independently of the code that made them.

## How it works

`src/authenticator.ts` is a software authenticator that builds the JSON a browser returns from `PublicKeyCredential.toJSON()`, with every field open to tampering. `src/cbor.ts` is a CBOR encoder that can also produce the encodings a correct encoder never would. `src/cases.ts` defines the cases.

Each adapter in `adapters/` is a small program that reads cases as JSON lines on stdin and prints one verdict per line. It uses its library's public API the way an application would, and for login cases it first registers the credential with the same library, then sets the stored counter. An adapter also flags rejections that come from an exception type the library does not document.

The cases carry fixed challenges, because the challenge is inside the signed data. Most libraries take the expected challenge as a parameter. go-webauthn and webauthn-rs generate it themselves: their adapters start the ceremony normally, then replace only the challenge in the stored ceremony state (for webauthn-rs, through its `danger-allow-state-serialisation` feature, which applications use to keep that state in a database). Library-specific notes:

- **webauthn-rs**: the passkey API always requires user verification and offers ES256 and RS256; 0.6 has no Ed25519, so EdDSA cases are marked unsupported.
- **webauthn4j**: configured with its attestation verifiers; `createNonStrictWebAuthnManager()` skips attestation verification by design.
- **webauthn-ruby**: default settings, including `verify_cross_origin: false`.

### Adding a library

Add a directory under `adapters/` with a program that:

1. prints `{"library": "...", "version": "...", "language": "..."}` when run with `--info`;
2. for each JSON line on stdin, prints `{"id": "<case id>", "verdict": "accept" | "reject", "error": "..."}`;

then add it to [`adapters/adapters.json`](adapters/adapters.json) with its build and run commands. Pull requests for more libraries are welcome.

## Prior art

- The [FIDO Alliance conformance tools](https://fidoalliance.org/certification/functional-certification/functional-certification-process-servers/) check that a server implements the specification, for certification. They are not public and do not compare implementations.
- [JWTeemo](https://github.com/JWTeemo/JWTeemo) ([NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-f697-paper.pdf)) did this for JWT libraries; [AuthSaber](https://ucla-sec-lab.netlify.app/publication/2024-authsaber) and [PrOfESSOS](https://nds.rub.de/media/ei/veroeffentlichungen/2017/01/30/oidc-security.pdf) for OpenID Connect; [Project Wycheproof](https://github.com/C2SP/wycheproof) for cryptographic primitives; [ParsEval](https://arxiv.org/abs/2405.18993) for X.509 parsers.

## Responsible use

The cases target libraries running locally. Do not point them at websites you do not own. If you find a security problem in a library with grimaldello, report it privately to its maintainers first.

## License

MIT. The keys in `src/keys/` and in `src/credential.ts` are test keys, public on purpose: never use them for anything else.
