"""grimaldello adapter for py_webauthn (Duo Labs).

Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.
"""

import json
import sys
from importlib.metadata import version

import webauthn
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException


def register(c):
    return webauthn.verify_registration_response(
        credential=c["registration"]["response"],
        expected_challenge=base64url_to_bytes(c["registration"]["challenge"]),
        expected_rp_id=c["rp"]["id"],
        expected_origin=c["rp"]["origin"],
        require_user_verification=c["requireUserVerification"],
        supported_pub_key_algs=[COSEAlgorithmIdentifier(a) for a in c["algorithms"]],
    )


def verify(c):
    if c["ceremony"] == "registration":
        register(c)
        return
    try:
        reg = register(c)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"setup: registration failed: {e}") from e
    a = c["authentication"]
    # What an application does: look the credential up by the id in the response.
    if a["response"]["id"] != bytes_to_base64url(reg.credential_id):
        raise RuntimeError("unknown credential")
    webauthn.verify_authentication_response(
        credential=a["response"],
        expected_challenge=base64url_to_bytes(a["challenge"]),
        expected_rp_id=c["rp"]["id"],
        expected_origin=c["rp"]["origin"],
        credential_public_key=reg.credential_public_key,
        credential_current_sign_count=a["storedSignCount"],
        require_user_verification=c["requireUserVerification"],
    )


def main():
    if "--info" in sys.argv:
        print(json.dumps({"library": "py_webauthn", "version": version("webauthn"), "language": "Python"}))
        return
    for line in sys.stdin:
        if not line.strip():
            continue
        c = json.loads(line)
        try:
            verify(c)
            out = {"id": c["id"], "verdict": "accept"}
        except Exception as e:  # noqa: BLE001
            out = {"id": c["id"], "verdict": "reject", "error": f"{type(e).__name__}: {e}"}
            # Applications catch WebAuthnException; anything else becomes a 500.
            root = e.__cause__ if isinstance(e, RuntimeError) and str(e).startswith("setup:") else e
            if not isinstance(root, WebAuthnException) and str(e) != "unknown credential":
                out["unexpected"] = True
        print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
