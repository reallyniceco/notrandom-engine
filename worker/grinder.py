"""Bounded adapter for the pinned cavemanloverboy/vanity CLI."""

import json
import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import base58
from nacl.signing import SigningKey

REVISION = "4e0f88d60f16f4e5336b2d688c119dd96173834e"
ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
FIELDS = {"prefix", "suffix", "case_insensitive", "count", "max_seconds", "gpus", "cpu_threads"}


def validate_input(data):
    if not isinstance(data, dict):
        raise ValueError("input must be a JSON object")
    if set(data) - FIELDS:
        raise ValueError("input contains unsupported fields")
    result = {
        "prefix": "" if data.get("suffix") else "kgc",
        "suffix": "",
        "case_insensitive": True,
        "count": 1,
        "max_seconds": 60,
        "gpus": 1,
        "cpu_threads": 1,
    } | data
    if type(result["case_insensitive"]) is not bool:
        raise ValueError("case_insensitive must be a boolean")
    for field in ("prefix", "suffix"):
        value = result[field]
        if not isinstance(value, str) or len(value) > 44:
            raise ValueError(f"{field} must be a string of at most 44 characters")
        # Accept O/I/l in insensitive requests by choosing their valid Base58 case.
        normalized = ""
        for char in value:
            if char in ALPHABET:
                normalized += char
            elif result["case_insensitive"] and char.swapcase() in ALPHABET:
                normalized += char.swapcase()
            else:
                raise ValueError(f"{field} contains a character that cannot match Base58")
        result[field] = normalized
    if not result["prefix"] and not result["suffix"]:
        raise ValueError("provide a nonempty prefix or suffix")
    for field, low, high in (
        ("count", 1, 10),
        ("max_seconds", 1, 86400),
        ("gpus", 1, 8),
        ("cpu_threads", 1, 16),
    ):
        if type(result[field]) is not int or not low <= result[field] <= high:
            raise ValueError(f"{field} must be an integer from {low} to {high}")
    return result


def verify_keypair(values, public_key, request):
    if (
        not isinstance(values, list)
        or len(values) != 64
        or any(type(n) is not int or not 0 <= n <= 255 for n in values)
    ):
        raise ValueError("backend produced an invalid keypair format")
    raw = bytes(values)
    signer = SigningKey(raw[:32])
    if bytes(signer.verify_key) != raw[32:]:
        raise ValueError("backend keypair failed independent Ed25519 verification")
    if base58.b58encode(raw[32:]).decode() != public_key:
        raise ValueError("backend public key does not match its keypair")
    address, prefix, suffix = public_key, request["prefix"], request["suffix"]
    if request["case_insensitive"]:
        address, prefix, suffix = address.lower(), prefix.lower(), suffix.lower()
    if not address.startswith(prefix) or not address.endswith(suffix):
        raise ValueError("backend keypair does not match the requested pattern")
    message = b"wallet-grinder-poc-keypair-check-v1"
    signer.verify_key.verify(message, signer.sign(message).signature)
    return {"public_key": public_key, "keypair": values}


def gpu_names():
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("NVIDIA GPU unavailable; deploy this image on an NVIDIA GPU worker") from None
    return [name.strip() for name in result.stdout.splitlines() if name.strip()]


def stop_process(process):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def parse_metrics(log):
    final = re.findall(r"done: ([\d,]+) attempts in .*? at ([\d,]+) attempts/sec", log)
    live = re.findall(r"([\d,]+) attempts \| ([\d,]+) attempts/sec", log)
    values = final or live
    return {
        "attempts": int(values[-1][0].replace(",", "")) if values else None,
        "reported_attempts_per_second": int(values[-1][1].replace(",", "")) if values else None,
        "metrics_final": bool(final),
    }


def grind(data):
    request = validate_input(data)
    backend = os.environ.get("GRINDER_BACKEND", "cuda")
    if backend not in {"cuda", "cpu"}:
        raise RuntimeError("GRINDER_BACKEND must be cuda or cpu")
    devices = gpu_names() if backend == "cuda" else []
    if backend == "cuda" and len(devices) < request["gpus"]:
        raise ValueError("requested more GPUs than this worker has")
    binary = os.environ.get("VANITY_BIN", "/usr/local/bin/vanity")
    command = [
        binary,
        "grind-keypair",
        "--pattern",
        f"{request['prefix']}...{request['suffix']}",
        "--count",
        str(request["count"]),
        "--num-cpus",
        str(request["cpu_threads"]),
    ]
    if backend == "cuda":
        command += ["--num-gpus", str(request["gpus"])]
    if request["case_insensitive"]:
        command.append("--case-insensitive")
    started = time.monotonic()
    timed_out = False
    # Each job gets its own directory. Never inherit another job's output keys.
    with tempfile.TemporaryDirectory(prefix="wallet-grinder-", dir=os.environ.get("GRINDER_PRIVATE_TMP")) as directory:
        with tempfile.TemporaryFile(dir=os.environ.get("GRINDER_PRIVATE_TMP")) as log_file:
            try:
                process = subprocess.Popen(
                    command, cwd=directory, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True, umask=0o077
                )
            except OSError:
                raise RuntimeError(
                    "could not start vanity; check VANITY_BIN and CUDA runtime libraries"
                ) from None
            try:
                process.wait(timeout=request["max_seconds"])
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                stop_process(process)
            # Only metrics and known error classes leave the private log file.
            log_file.seek(max(0, log_file.tell() - 65536))
            log = log_file.read().decode("utf-8", errors="replace")
        if not timed_out and process.returncode != 0:
            hint = "CUDA/backend failure"
            if "no kernel image" in log:
                hint = "image does not support this GPU; rebuild with its VANITY_CUDA_ARCH"
            elif "cudaMalloc" in log:
                hint = "GPU memory allocation failed"
            raise RuntimeError(f"vanity exited with code {process.returncode}: {hint}")
        wallets = []
        for path in sorted(Path(directory).glob("*.json")):
            try:
                values = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                if timed_out:
                    continue  # A forced stop may interrupt the final file write.
                raise RuntimeError("backend wrote an unreadable keypair") from None
            wallets.append(verify_keypair(values, path.stem, request))
        if not timed_out and len(wallets) != request["count"]:
            raise RuntimeError("backend exited without the requested number of verified keypairs")
    return {
        "status": "completed" if len(wallets) >= request["count"] else "timed_out",
        "backend": backend,
        "upstream_revision": REVISION,
        "request": request,
        "gpu_names": devices[: request["gpus"]],
        "wallets": wallets,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "deadline_reached": timed_out,
        **parse_metrics(log),
    }
