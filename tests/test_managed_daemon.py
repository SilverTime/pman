import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.request import urlopen

import helpers  # noqa: F401

from pman.vault import Vault


class ManagedDaemonIntegrationTest(unittest.TestCase):
    def test_desktop_style_stdin_unlock_starts_ready_daemon(self):
        password = "integration-only-password"
        with tempfile.TemporaryDirectory() as home:
            old_iterations = os.environ.get("PM_KDF_ITERATIONS")
            os.environ["PM_KDF_ITERATIONS"] = "1000"
            try:
                vault = Vault(Path(home))
                vault.create(password)
                vault.close()
            finally:
                if old_iterations is None:
                    os.environ.pop("PM_KDF_ITERATIONS", None)
                else:
                    os.environ["PM_KDF_ITERATIONS"] = old_iterations

            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]

            env = os.environ.copy()
            env.update(
                {
                    "PM_HOME": home,
                    "PM_KDF_ITERATIONS": "1000",
                    "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
                }
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "pman.cli",
                    "daemon",
                    "--port",
                    str(port),
                    "--password-stdin",
                    "--parent-pid",
                    str(os.getpid()),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            try:
                process.stdin.write(password + "\n")
                process.stdin.close()
                status = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        error = process.stderr.read()
                        self.fail(f"managed daemon exited early: {error}")
                    try:
                        with urlopen(f"http://127.0.0.1:{port}/v1/status", timeout=0.25) as response:
                            status = json.load(response)
                        break
                    except OSError:
                        time.sleep(0.05)
                self.assertIsNotNone(status, "managed daemon did not become ready")
                self.assertTrue(status["unlocked"])
                self.assertEqual(status["protocol"], "pman")
                self.assertEqual(status["protocol_version"], 2)
            finally:
                try:
                    if process.poll() is None:
                        if os.name == "nt":
                            # Windows virtualenv launchers can own a separate
                            # interpreter process. Stop only this test's tree.
                            subprocess.run(
                                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE,
                                check=True,
                            )
                        else:
                            process.terminate()
                    process.wait(timeout=5)
                finally:
                    process.stderr.close()


if __name__ == "__main__":
    unittest.main()
