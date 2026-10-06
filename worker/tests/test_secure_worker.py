import base64
import json
import uuid
from copy import deepcopy

import base58
import pytest
from jwcrypto import jwe, jwk
from nacl.signing import SigningKey

import secure_worker


@pytest.fixture(scope="module")
def recipient():
    return jwk.JWK.generate(kty="RSA", size=3072)


@pytest.fixture
def job(recipient):
    public = json.loads(recipient.export_public())
    return {
        "input": {
            "protocol": "notrandom-v1",
            "order_id": str(uuid.uuid4()),
            "recipient_jwk": public,
            "request_hash": "a" * 64,
            "shard": 0,
            "request": {
                "prefix": "k",
                "case_insensitive": True,
                "count": 1,
                "gpus": 1,
                "cpu_threads": 1,
                "max_seconds": 10,
            },
        }
    }


@pytest.mark.parametrize("shard", [0, 128, 647, 1023, 2047, 2**53 - 1])
def test_encrypted_delivery_and_binding(job, recipient, monkeypatch, shard):
    job["input"]["shard"] = shard
    signing = SigningKey.generate()
    keypair = list(bytes(signing) + bytes(signing.verify_key))
    address = base58.b58encode(bytes(signing.verify_key)).decode()
    monkeypatch.setattr(
        secure_worker,
        "grind",
        lambda _: {
            "status": "completed",
            "wallets": [{"public_key": address, "keypair": keypair[:]}],
            "attempts": 42,
            "elapsed_seconds": 0.01,
        },
    )
    result = secure_worker.handle_secure_job(job)
    assert result["shard"] == shard
    wire = json.dumps(result)
    assert "wallets" not in result and "keypair" not in wire
    assert json.dumps(keypair) not in wire
    assert result["result"]["recipient_thumbprint"] == recipient.thumbprint()
    message = jwe.JWE(algs=["RSA-OAEP-256", "A256GCM"])
    message.deserialize(result["result"]["jwe"], key=recipient)
    payload = json.loads(message.payload)
    assert payload["keypair"] == keypair
    assert payload["public_key"] == address
    assert payload["order_id"] == job["input"]["order_id"]
    assert payload["request_hash"] == job["input"]["request_hash"]
    parts = result["result"]["jwe"].split(".")
    parts[-1] = ("A" if parts[-1][0] != "A" else "B") + parts[-1][1:]
    with pytest.raises(jwe.InvalidJWEData):
        jwe.JWE().deserialize(".".join(parts), key=recipient)
    with pytest.raises(jwe.InvalidJWEData):
        jwe.JWE().deserialize(result["result"]["jwe"], key=jwk.JWK.generate(kty="RSA", size=3072))


def test_timeout_returns_metrics_without_secret(job, monkeypatch):
    monkeypatch.setattr(
        secure_worker, "grind", lambda _: {"status": "timed_out", "wallets": [], "attempts": 200}
    )
    result = secure_worker.handle_secure_job(job)
    assert result["result"] is None
    assert result["attempts"] == 200
    assert "wallets" not in result


@pytest.mark.parametrize(
    "field,value",
    [
        ("protocol", "wrong"),
        ("shard", True),
        ("shard", -1),
        ("shard", 2**53),
        ("shard", 1.5),
        ("shard", "128"),
        ("order_id", "wrong"),
        ("request_hash", "bad"),
    ],
)
def test_invalid_binding_rejected_before_grind(job, monkeypatch, field, value):
    job["input"][field] = value
    monkeypatch.setattr(secure_worker, "grind", lambda _: pytest.fail("grind must not run"))
    with pytest.raises(ValueError):
        secure_worker.handle_secure_job(job)


def test_reject_private_and_weak_encryption_keys(job, recipient):
    private = json.loads(recipient.export_private())
    with pytest.raises(ValueError):
        secure_worker.validate_recipient(private)
    with pytest.raises(ValueError):
        secure_worker.validate_recipient(json.loads(jwk.JWK.generate(kty="RSA", size=2048).export_public()))
    bad = deepcopy(job["input"]["recipient_jwk"])
    bad["n"] = base64.urlsafe_b64encode(b"\x00" * 384).decode().rstrip("=")
    with pytest.raises(ValueError):
        secure_worker.validate_recipient(bad)
