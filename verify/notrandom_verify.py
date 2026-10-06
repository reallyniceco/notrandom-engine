#!/usr/bin/env python3
"""Open and check a notrandom.fun order on your own computer.

This is a second implementation of the notrandom-v1 protocol (see PROTOCOL.md),
written separately from the website. It reads your recovery file and, if you
give it one, your order as returned by our API. It never touches the network.

    python notrandom_verify.py RECOVERY.json [ORDER.json] [--save-keypair PATH]

Exit codes: 0 every check passed, 1 a check failed, 2 bad input, 3 the order
has no result yet.
"""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys
import uuid

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTOCOL = "notrandom-v1"
JWE_TYPE = "notrandom-result+jwe"
# The seven purchase fields, in the order the API hashes them.
REQUEST_KEYS = ("input", "case_sensitive", "estimated_time", "estimated_cost", "rush", "type", "buyer")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B64URL = re.compile(r"[A-Za-z0-9_-]*")


class CheckFailed(Exception):
    """The order does not hold together. Never ignore this."""


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def b64url_decode(text):
    if not isinstance(text, str) or not B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise CheckFailed("malformed base64url value")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def base58_encode(data):
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, digit = divmod(number, 58)
        out = B58[digit] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def js_number(value):
    """Format a number exactly as JavaScript's JSON.stringify does."""
    if isinstance(value, int) and abs(value) <= 2**53:
        return str(value)
    value = float(value)
    if not math.isfinite(value):
        return "null"
    if value == 0:
        return "0"
    # repr() gives the same shortest round-trip digits JavaScript uses;
    # only the layout rules differ (ECMAScript Number::toString).
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = whole + fraction
    zeros = len(digits) - len(digits.lstrip("0"))
    point = len(whole) - zeros + int(exponent or 0)
    digits = digits.strip("0")
    count = len(digits)
    if count <= point <= 21:
        text = digits + "0" * (point - count)
    elif 0 < point <= 21:
        text = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        text = "0." + "0" * -point + digits
    else:
        power = point - 1
        text = digits[0] + ("." + digits[1:] if count > 1 else "") + ("e+" if power >= 0 else "e-") + str(abs(power))
    return ("-" if value < 0 else "") + text


def js_json(value):
    """JSON.stringify(value) for the plain JSON values the protocol hashes."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return js_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(js_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(js_json(key) + ":" + js_json(item) for key, item in value.items()) + "}"
    raise CheckFailed("unexpected value in request")


def public_recipient(recovery):
    recipient = recovery.get("recipient")
    require(
        isinstance(recipient, dict) and set(recipient) == {"kty", "n", "e"},
        "recovery file has no public encryption key",
    )
    require(recipient["kty"] == "RSA" and recipient["e"] == "AQAB", "encryption key must be RSA with e=65537")
    return {"kty": "RSA", "n": recipient["n"], "e": "AQAB"}


def thumbprint(recipient):
    """RFC 7638 SHA-256 thumbprint: the key's ID in every order and result."""
    canonical = json.dumps({"e": recipient["e"], "kty": "RSA", "n": recipient["n"]}, separators=(",", ":"))
    return b64url_encode(hashlib.sha256(canonical.encode()).digest())


def request_hash(request, recipient):
    require(isinstance(request, dict) and set(request) == set(REQUEST_KEYS), "recovery file has an unexpected request")
    ordered = {key: request[key] for key in REQUEST_KEYS}
    return hashlib.sha256(js_json({"request": ordered, "recipient": recipient}).encode()).hexdigest()


def private_key(recovery, recipient):
    jwk = recovery.get("private_jwk")
    fields = ("n", "e", "d", "p", "q", "dp", "dq", "qi")
    require(isinstance(jwk, dict) and jwk.get("kty") == "RSA", "recovery file has no private key")
    require(all(isinstance(jwk.get(name), str) for name in fields), "recovery file's private key is incomplete")
    require(jwk["n"] == recipient["n"] and jwk["e"] == recipient["e"], "private key does not match the public key")
    number = {name: int.from_bytes(b64url_decode(jwk[name]), "big") for name in fields}
    try:
        key = rsa.RSAPrivateNumbers(
            p=number["p"],
            q=number["q"],
            d=number["d"],
            dmp1=number["dp"],
            dmq1=number["dq"],
            iqmp=number["qi"],
            public_numbers=rsa.RSAPublicNumbers(number["e"], number["n"]),
        ).private_key()
    except ValueError:
        raise CheckFailed("recovery file's private key is not a valid RSA key") from None
    require(key.key_size in (3072, 4096), "encryption key must be 3072 or 4096 bits")
    return key


OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def check_recovery(recovery):
    """Checks the file your browser saved, before any result exists."""
    require(isinstance(recovery, dict) and recovery.get("protocol") == PROTOCOL, "not a notrandom-v1 recovery file")
    order_id = recovery.get("id")
    try:
        require(isinstance(order_id, str) and str(uuid.UUID(order_id)) == order_id, "invalid order ID")
    except ValueError:
        raise CheckFailed("invalid order ID") from None
    recipient = public_recipient(recovery)
    key = private_key(recovery, recipient)
    # Prove the pair works: seal a random value to the public half, open it with the private half.
    probe = os.urandom(32)
    require(key.decrypt(key.public_key().encrypt(probe, OAEP), OAEP) == probe, "private key cannot open its own lock")
    kid = thumbprint(recipient)
    require(recovery.get("recipient_thumbprint") == kid, "recovery file's key ID does not match its key")
    require(
        recovery.get("request_hash") == request_hash(recovery.get("request"), recipient),
        "recovery file's request hash does not match its request and key",
    )
    return {"id": order_id, "key": key, "kid": kid, "request": recovery["request"], "hash": recovery["request_hash"]}


def decrypt_jwe(compact, key, kid):
    """Compact JWE, RSA-OAEP-256 + A256GCM (RFC 7516), with nothing else allowed."""
    require(isinstance(compact, str) and compact.count(".") == 4, "sealed result is not a compact JWE")
    encoded_header, encrypted_key, iv, ciphertext, tag = compact.split(".")
    try:
        header = json.loads(b64url_decode(encoded_header))
    except ValueError:
        raise CheckFailed("sealed result has an unreadable header") from None
    require(isinstance(header, dict), "sealed result has an unreadable header")
    require(
        header == {"alg": "RSA-OAEP-256", "enc": "A256GCM", "typ": JWE_TYPE, "kid": kid},
        "sealed result's header is not sealed to your key with RSA-OAEP-256 and A256GCM",
    )
    try:
        content_key = key.decrypt(b64url_decode(encrypted_key), OAEP)
    except ValueError:
        raise CheckFailed("your private key cannot open this result") from None
    nonce, sealed, mac = b64url_decode(iv), b64url_decode(ciphertext), b64url_decode(tag)
    require(len(content_key) == 32 and len(nonce) == 12 and len(mac) == 16, "sealed result has malformed parts")
    try:
        return AESGCM(content_key).decrypt(nonce, sealed + mac, encoded_header.encode("ascii"))
    except InvalidTag:
        raise CheckFailed("sealed result was altered after it was sealed") from None


def matches(address, request):
    word = request["input"]
    if request["case_sensitive"]:
        return address.startswith(word)
    return address.lower().startswith(word.lower())


def open_result(order, ticket):
    """Checks an API order (or just its `result`) against the recovery file."""
    require(isinstance(order, dict), "order file is not a JSON object")
    envelope = order
    if "jwe" not in order:
        require(order.get("id") == ticket["id"], "this order belongs to a different order ID")
        require(order.get("request_hash") == ticket["hash"], "our API holds a different request for this order")
        require(order.get("recipient_thumbprint") == ticket["kid"], "our API holds a different encryption key")
        envelope = order.get("result")
        if envelope is None:
            return None
    require(isinstance(envelope, dict), "order result is not a JSON object")
    require(
        envelope.get("protocol") == PROTOCOL
        and envelope.get("order_id") == ticket["id"]
        and envelope.get("recipient_thumbprint") == ticket["kid"],
        "this result belongs to a different order or key",
    )
    try:
        payload = json.loads(decrypt_jwe(envelope.get("jwe"), ticket["key"], ticket["kid"]))
    except ValueError:
        raise CheckFailed("sealed result does not contain JSON") from None
    require(isinstance(payload, dict), "sealed result does not contain a JSON object")
    require(
        payload.get("protocol") == PROTOCOL
        and payload.get("order_id") == ticket["id"]
        and payload.get("request_hash") == ticket["hash"],
        "sealed result was made for a different order",
    )
    require(payload.get("public_key") == envelope.get("public_key"), "sealed address differs from the listed address")
    values = payload.get("keypair")
    require(
        isinstance(values, list) and len(values) == 64 and all(type(n) is int and 0 <= n <= 255 for n in values),
        "sealed result contains a malformed key",
    )
    keypair = bytes(values)
    signer = Ed25519PrivateKey.from_private_bytes(keypair[:32])
    derived = signer.public_key().public_bytes_raw()
    require(derived == keypair[32:], "the private key does not produce the public key stored with it")
    address = base58_encode(derived)
    require(address == envelope["public_key"], "the private key does not produce the listed address")
    message = b"notrandom-verify " + ticket["id"].encode()
    try:
        Ed25519PublicKey.from_public_bytes(derived).verify(signer.sign(message), message)
    except InvalidSignature:
        raise CheckFailed("the private key cannot sign for its address") from None
    require(matches(address, ticket["request"]), f"the address does not start with {ticket['request']['input']!r}")
    return {"address": address, "keypair": values}


def save_keypair(path, values):
    """Solana CLI keypair file: 64 bytes, seed then public key. Owner-only."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as file:
        json.dump(values, file)


def load(path, label):
    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError) as error:
        print(f"Can't read the {label} {path}: {error}", file=sys.stderr)
        sys.exit(2)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Open and check a notrandom.fun order offline.")
    parser.add_argument("recovery", help="the recovery file notrandom.fun saved for your order")
    parser.add_argument("order", nargs="?", help="your order JSON from the API, or just its result")
    parser.add_argument("--save-keypair", metavar="PATH", help="also write the wallet as a Solana CLI keypair file")
    args = parser.parse_args(argv)
    recovery = load(args.recovery, "recovery file")
    order = load(args.order, "order file") if args.order else None
    try:
        ticket = check_recovery(recovery)
        print(f"✓ Order {ticket['id']}: this file holds your RSA-{ticket['key'].key_size} lock and the key that opens it.")
        print("✓ The order's request hash and key ID match this file.")
        if order is None:
            print("\nAdd your order JSON to open the result. See README.md for where to find it.")
            return 0
        opened = open_result(order, ticket)
        if opened is None:
            print(f"\nNo result yet: the order's status is {order.get('status')!r}.")
            return 3
        if "jwe" not in order:
            print("✓ Our API stored your lock and your request, unchanged.")
        print("✓ The result is sealed to your lock, and nothing altered it.")
        print("✓ Inside: a private key that produces its address and signs for it.")
        print(f"✓ The address starts with {ticket['request']['input']!r}.")
        print(f"\nYour address: {opened['address']}")
        if args.save_keypair:
            try:
                save_keypair(args.save_keypair, opened["keypair"])
            except OSError as error:
                print(f"Can't write {args.save_keypair}: {error}", file=sys.stderr)
                return 2
            print(f"Saved the keypair to {args.save_keypair} (only you can read it).")
        return 0
    except CheckFailed as error:
        print(f"✗ {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
