"""Run a real Uvicorn server and exercise it with the system curl client."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import uvicorn


def _wait_until_ready(url: str, *, timeout_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.5):  # noqa: S310
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server did not become ready at {url}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    curl = shutil.which("curl.exe") or shutil.which("curl")
    if curl is None:
        raise RuntimeError("curl executable was not found")

    root = Path(__file__).parents[1]
    fixture = root / "samples" / "multi_source_demo.log"
    base_url = f"http://127.0.0.1:{args.port}"
    server = uvicorn.Server(
        uvicorn.Config(
            "ai_soc_agent.server:app",
            host="127.0.0.1",
            port=args.port,
            log_level="warning",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    try:
        _wait_until_ready(f"{base_url}/alerts")
        ingest = subprocess.run(
            [
                curl,
                "-sS",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                f"@{fixture}",
                f"{base_url}/ingest",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        alerts = subprocess.run(
            [curl, "-sS", f"{base_url}/alerts"],
            check=True,
            capture_output=True,
            text=True,
        )
        print("CURL_INGEST")
        print(ingest.stdout)
        print("CURL_ALERTS")
        print(alerts.stdout)
    finally:
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
