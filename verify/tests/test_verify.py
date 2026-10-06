"""The verifier against the real worker code: what the worker seals, the verifier opens."""

import base64
import json
import os
import stat
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import notrandom_verify as verify
import secure_worker

# JSON.stringify output from Node 24, so the request hash matches the browser and API.
JS_NUMBERS = [
    "0", "1", "12", "12.5", "0.1", "0.00005", "0.000001", "1e-7", "123456.789", "1234567890123456800",
    "1e+21", "1.5e+21", "3.2e+25", "9007199254740992", "4.2e-10", "100", "2500000000000000",
    "10000000000000000", "12345678901234567000", "0.30000000000000004", "299.99", "6.25",
]


@pytest.mark.parametrize("text", JS_NUMBERS)
def test_numbers_format_like_javascript(text):
    assert verify.js_number(json.loads(text)) == text
    assert verify.js_number(float(text)) == text


def test_request_hash_matches_javascript():
    request = {
        "input": "NoTR4nd",
        "case_sensitive": False,
        "estimated_time": 12345678901234567890,
        "estimated_cost": 0.00005,
        "rush": True,
        "type": "coin",
        "buyer": "NTRNDMczz1bzzB3eYk5VdMdovbf223wFuq57FEjqkoA",
    }
    recipient = {"kty": "RSA", "n": "x" * 512, "e": "AQAB"}
    expected = "7dbc452927e8564cc89515ceb7d01b7b0de06a5f68db6add5e559505a4ae6c1d"
    assert verify.request_hash(request, recipient) == expected
    # Key order in the file doesn't matter; the API's order does.
    assert verify.request_hash(dict(reversed(request.items())), recipient) == expected


def test_base58_matches_known_addresses():
    assert verify.base58_encode(bytes(32)) == "1" * 32
    assert verify.base58_encode(bytes([0, 0, 1])) == "112"


def b64(number):
    return base64.urlsafe_b64encode(number.to_bytes((number.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def wallet():
    signer = Ed25519PrivateKey.generate()
    seed = signer.private_bytes_raw()
    public = signer.public_key().public_bytes_raw()
    return verify.base58_encode(public), list(seed + public)


def make_recovery(rsa_key, word, case_sensitive=False):
    """What the browser saves: see createRecovery in PROTOCOL.md."""
    private = rsa_key.private_numbers()
    recipient = {"kty": "RSA", "n": b64(private.public_numbers.n), "e": "AQAB"}
    request = {
        "input": word,
        "case_sensitive": case_sensitive,
        "estimated_time": 41.73,
        "estimated_cost": 6.25,
        "rush": False,
        "type": "wallet",
        "buyer": "NTRNDMczz1bzzB3eYk5VdMdovbf223wFuq57FEjqkoA",
    }
    return {
        "protocol": "notrandom-v1",
        "id": str(uuid.uuid4()),
        "token": "A" * 43,
        "request": request,
        "recipient": recipient,
        "recipient_thumbprint": verify.thumbprint(recipient),
        "request_hash": verify.request_hash(request, recipient),
        "private_jwk": {
            "kty": "RSA",
            "n": recipient["n"],
            "e": "AQAB",
            "d": b64(private.d),
            "p": b64(private.p),
            "q": b64(private.q),
            "dp": b64(private.dmp1),
            "dq": b64(private.dmq1),
            "qi": b64(private.iqmp),
        },
        "created_at": 1791244800000,
    }


def seal(recovery, wallet, monkeypatch):
    """Runs the published worker code, with the engine replaced by a known keypair."""
    address, keypair = wallet
    monkeypatch.setattr(
        secure_worker,
        "grind",
        lambda request: {"status": "completed", "wallets": [{"public_key": address, "keypair": keypair[:]}]},
    )
    job = {
        "input": {
            "protocol": "notrandom-v1",
            "order_id": recovery["id"],
            "recipient_jwk": recovery["recipient"],
            "request": {"prefix": recovery["request"]["input"], "case_insensitive": True},
            "shard": 0,
            "request_hash": recovery["request_hash"],
        }
    }
    return secure_worker.handle_secure_job(job)["result"]


def make_order(recovery, envelope, status="completed"):
    return {
        "protocol": "notrandom-v1",
        "id": recovery["id"],
        "type": "wallet",
        "status": status,
        "request": recovery["request"],
        "request_hash": recovery["request_hash"],
        "recipient_thumbprint": recovery["recipient_thumbprint"],
        "result": envelope,
    }


@pytest.fixture
def files(tmp_path, rsa_key, wallet, monkeypatch):
    def write(recovery=None, order=None, word=None):
        recovery = recovery or make_recovery(rsa_key, word or wallet[0][:3].swapcase())
        order = order or make_order(recovery, seal(recovery, wallet, monkeypatch))
        paths = tmp_path / "recovery.json", tmp_path / "order.json"
        paths[0].write_text(json.dumps(recovery))
        paths[1].write_text(json.dumps(order))
        return recovery, order, [str(path) for path in paths]

    return write


def test_opens_what_the_worker_sealed(files, wallet, tmp_path, capsys):
    _, _, paths = files()
    keyfile = tmp_path / "wallet.json"
    assert verify.main([*paths, "--save-keypair", str(keyfile)]) == 0
    out = capsys.readouterr().out
    assert f"Your address: {wallet[0]}" in out
    assert json.loads(keyfile.read_text()) == wallet[1]
    assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600
    # Never overwrite an existing file, least of all a key.
    assert verify.main([*paths, "--save-keypair", str(keyfile)]) == 2


def test_accepts_just_the_result(files, wallet, tmp_path, capsys):
    _, order, paths = files()
    (tmp_path / "result.json").write_text(json.dumps(order["result"]))
    assert verify.main([paths[0], str(tmp_path / "result.json")]) == 0
    assert wallet[0] in capsys.readouterr().out


def test_recovery_alone_and_pending_order(files, rsa_key, tmp_path):
    recovery, _, paths = files()
    assert verify.main([paths[0]]) == 0
    (tmp_path / "pending.json").write_text(json.dumps(make_order(recovery, None, status="running")))
    assert verify.main([paths[0], str(tmp_path / "pending.json")]) == 3


def tampered_jwe(order):
    parts = order["result"]["jwe"].split(".")
    parts[3] = ("A" if parts[3][0] != "A" else "B") + parts[3][1:]
    order["result"]["jwe"] = ".".join(parts)


def swapped_address(order):
    order["result"]["public_key"] = verify.base58_encode(os.urandom(32))


@pytest.mark.parametrize(
    "tamper,message",
    [
        (tampered_jwe, "altered"),
        (swapped_address, "listed address"),
        (lambda o: o.update(request_hash="0" * 64), "different request"),
        (lambda o: o.update(recipient_thumbprint="x"), "different encryption key"),
        (lambda o: o["result"].update(order_id=str(uuid.uuid4())), "different order"),
        (lambda o: o.update(id=str(uuid.uuid4())), "different order ID"),
    ],
)
def test_rejects_altered_orders(files, capsys, tamper, message):
    recovery, order, _ = files()
    tamper(order)
    _, _, paths = files(recovery=recovery, order=order)
    assert verify.main(paths) == 1
    assert message in capsys.readouterr().err


def test_rejects_result_sealed_to_another_key(files, wallet, monkeypatch, capsys):
    other = make_recovery(rsa.generate_private_key(public_exponent=65537, key_size=3072), "x")
    recovery, _, _ = files()
    stolen = seal({**other, "id": recovery["id"], "request_hash": recovery["request_hash"]}, wallet, monkeypatch)
    _, _, paths = files(recovery=recovery, order=make_order(recovery, stolen))
    assert verify.main(paths) == 1
    assert "different order or key" in capsys.readouterr().err


def test_rejects_wrong_word(files, rsa_key, wallet, monkeypatch, capsys):
    recovery = make_recovery(rsa_key, "zzzz" if not wallet[0].lower().startswith("zzzz") else "yyyy")
    _, _, paths = files(recovery=recovery, order=make_order(recovery, seal(recovery, wallet, monkeypatch)))
    assert verify.main(paths) == 1
    assert "does not start with" in capsys.readouterr().err


def test_case_sensitive_word(files, rsa_key, wallet, monkeypatch):
    for word, expected in ((wallet[0][:3], 0), (wallet[0][:3].swapcase(), 1)):
        if word == word.swapcase():
            continue  # digits only: case can't differ
        recovery = make_recovery(rsa_key, word, case_sensitive=True)
        _, _, paths = files(recovery=recovery, order=make_order(recovery, seal(recovery, wallet, monkeypatch)))
        assert verify.main(paths) == expected


@pytest.mark.parametrize(
    "tamper,message",
    [
        (lambda r: r["request"].update(rush=True), "request hash"),
        (lambda r: r.update(recipient_thumbprint="x"), "key ID"),
        (lambda r: r["private_jwk"].update(n=r["private_jwk"]["n"][:-2] + "AA"), "does not match"),
        (lambda r: r["private_jwk"].update(d=r["private_jwk"]["p"]), "not a valid RSA key"),
        (lambda r: r.update(protocol="notrandom-v0"), "not a notrandom-v1"),
    ],
)
def test_rejects_altered_recovery_files(files, rsa_key, tmp_path, capsys, tamper, message):
    recovery = make_recovery(rsa_key, "x")
    tamper(recovery)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(recovery))
    assert verify.main([str(path)]) == 1
    assert message in capsys.readouterr().err
