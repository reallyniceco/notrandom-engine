import json
import os
import signal
import sys
import tempfile
import time
from pathlib import Path

import base58
import pytest
from nacl.signing import SigningKey

import grinder


def handler(job):
    return grinder.grind(job["input"])


@pytest.fixture
def key():
    signing = SigningKey(bytes(range(32)))
    public = bytes(signing.verify_key)
    return base58.b58encode(public).decode(), list(bytes(signing) + public)


@pytest.fixture
def fake_backend(tmp_path, monkeypatch, key):
    address, values = key

    def install(extra="", corrupt=False):
        binary = tmp_path / "vanity"
        data = values.copy()
        if corrupt:
            data[0] ^= 1
        binary.write_text(
            f"#!{sys.executable}\nimport os, json, signal, time\n"
            f"open({address + '.json'!r}, 'w').write({json.dumps(data)!r})\n"
            "print('done: 1,234 attempts in 1s at 1,234 attempts/sec', flush=True)\n" + extra
        )
        binary.chmod(0o700)
        monkeypatch.setenv("VANITY_BIN", str(binary))
        monkeypatch.setenv("GRINDER_BACKEND", "cpu")
        return {"prefix": address[:2], "max_seconds": 5}

    return install


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {"prefix": ""},
        {"prefix": "0"},
        {"prefix": "../"},
        {"prefix": "a" * 45},
        {"count": True},
        {"count": 0},
        {"max_seconds": 86401},
        {"max_seconds": 1.5},
        {"gpus": 0},
        {"case_insensitive": "false"},
        {"shell": "anything"},
        {"prefix": "é"},
        {"prefix": "O", "case_insensitive": False},
    ],
)
def test_invalid_requests(data):
    with pytest.raises(ValueError):
        grinder.validate_input(data)


def test_defaults_and_suffix():
    assert grinder.validate_input({})["prefix"] == "kgc"
    assert grinder.validate_input({"suffix": "pump"})["prefix"] == ""
    assert grinder.validate_input({"prefix": "POPOFF"})["prefix"] == "PoPoFF"
    assert grinder.validate_input({"prefix": "lI"})["prefix"] == "Li"


def test_keypair_verification(key):
    address, values = key
    req = grinder.validate_input({"prefix": address[:3].swapcase()})
    assert grinder.verify_keypair(values, address, req)["public_key"] == address
    with pytest.raises(ValueError, match="pattern"):
        grinder.verify_keypair(values, address, grinder.validate_input({"prefix": "zzzz"}))
    with pytest.raises(ValueError, match="public key"):
        grinder.verify_keypair(values, address + "1", req)


def test_subprocess_success_and_cleanup(fake_backend, monkeypatch):
    request = fake_backend()
    paths = []
    original = grinder.verify_keypair

    def verify(*args):
        paths.extend(Path(tempfile.gettempdir()).glob("wallet-grinder-*"))
        return original(*args)

    monkeypatch.setattr(grinder, "verify_keypair", verify)
    result = handler({"input": request})
    assert result["status"] == "completed"
    assert result["attempts"] == 1234
    assert result["metrics_final"] is True
    assert result["backend"] == "cpu"
    assert len(result["wallets"]) == 1
    assert paths and all(not path.exists() for path in paths)


def test_reject_corrupt_output(fake_backend):
    with pytest.raises(ValueError, match="Ed25519"):
        handler({"input": fake_backend(corrupt=True)})


def test_backend_failure_does_not_expose_log(fake_backend):
    request = fake_backend("print('sensitive-backend-output'); raise SystemExit(9)\n")
    with pytest.raises(RuntimeError) as error:
        handler({"input": request})
    assert "code 9" in str(error.value)
    assert "sensitive" not in str(error.value)


def test_timeout_keeps_partial_results_and_kills_process(fake_backend, tmp_path):
    pid_file = tmp_path / "pid"
    request = fake_backend(
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\ntime.sleep(60)\n"
    )
    request.update(max_seconds=1, count=2)
    started = time.monotonic()
    result = handler({"input": request})
    assert result["status"] == "timed_out"
    assert result["deadline_reached"] is True
    assert len(result["wallets"]) == 1
    assert time.monotonic() - started < 7
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), signal.SIGCONT)


def test_cuda_passes_flags(fake_backend, monkeypatch):
    request = fake_backend(
        "import sys\nassert '--num-gpus' in sys.argv\nassert '--case-insensitive' in sys.argv\n"
    )
    monkeypatch.setenv("GRINDER_BACKEND", "cuda")
    monkeypatch.setattr(grinder, "gpu_names", lambda: ["test GPU"])
    assert handler({"input": request})["gpu_names"] == ["test GPU"]
    with pytest.raises(ValueError, match="more GPUs"):
        handler({"input": request | {"gpus": 2}})


def test_no_gpu_no_silent_cpu_fallback(monkeypatch):
    monkeypatch.setenv("GRINDER_BACKEND", "cuda")
    monkeypatch.setattr(grinder, "gpu_names", lambda: [])
    with pytest.raises(ValueError):
        handler({"input": {}})


def test_live_metrics():
    assert grinder.parse_metrics("12,345 attempts | 3,456 attempts/sec") == {
        "attempts": 12345,
        "reported_attempts_per_second": 3456,
        "metrics_final": False,
    }
    assert grinder.parse_metrics("")["attempts"] is None


@pytest.mark.skipif(not os.environ.get("REAL_VANITY_BIN"), reason="set REAL_VANITY_BIN for real Rust test")
def test_real_rust_keypairs(monkeypatch):
    monkeypatch.setenv("VANITY_BIN", os.environ["REAL_VANITY_BIN"])
    monkeypatch.setenv("GRINDER_BACKEND", "cpu")
    for request in (
        {"prefix": "p", "case_insensitive": True, "count": 2},
        {"prefix": "", "suffix": "p", "case_insensitive": False},
    ):
        result = handler({"input": request | {"max_seconds": 30}})
        assert result["status"] == "completed"
        assert len(result["wallets"]) == request.get("count", 1)
        assert result["attempts"] > 0
