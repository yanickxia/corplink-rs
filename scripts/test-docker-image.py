#!/usr/bin/env python3
"""Exercise the shipped image without contacting a real CorpLink server."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


def run(arguments):
    return subprocess.run(
        arguments, text=True, capture_output=True, timeout=30, check=False
    )


def main(image):
    base = [
        "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
    ]
    result = run(base + [image, "--help"])
    # This CLI intentionally returns 1 for --help.
    assert result.returncode == 1 and "usage:" in result.stdout, result
    assert "running corplink-rs@" in result.stderr, result

    result = run(base + [
        "--entrypoint", "/bin/sh", image, "-ec",
        'test "$(id -u)" = 10001; '
        'test ! -e /config/config.json; '
        'test ! -d /src; test ! -d /usr/local/go; '
        'ldd /usr/local/bin/corplink-rs-dev',
    ])
    assert result.returncode == 0 and "not found" not in result.stdout, result

    with tempfile.TemporaryDirectory(prefix="corplink-docker-smoke-") as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps({
            "company_name": "synthetic-company",
            "username": "synthetic-user",
            "server": "http://127.0.0.1:9",
            "device_name": "docker-smoke-test",
            "interface_name": "docker-smoke-test",
            "login_flow": "device",
            "platform": "bytedance_sso",
            "auto_setup_routes": False,
            "use_vpn_dns": False,
            "socks5_listen": "0.0.0.0:1080",
            "state": "Init",
        }))
        path.chmod(0o600)
        invocation = base + [
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--mount", f"type=bind,source={directory},target=/config", image,
        ]
        first = run(invocation)
        assert first.returncode == 1, first
        assert "request LoginMethod failed" in first.stderr, first
        assert "please run as root" not in first.stderr, first
        assert "failed to write" not in first.stderr, first
        persisted = json.loads(path.read_text())
        for key in ("private_key", "public_key", "device_id"):
            assert persisted[key], key
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

        # Recreating the container must reuse the generated identity on the volume.
        second = run(invocation)
        assert second.returncode == 1, second
        assert "request LoginMethod failed" in second.stderr, second
        restarted = json.loads(path.read_text())
        for key in ("private_key", "public_key", "device_id"):
            assert persisted[key] == restarted[key], key

    print(f"{image}: non-root runtime, dependencies and persistent identity: PASS")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} IMAGE")
    main(sys.argv[1])
