"""Check packaging configuration before any game files are modified."""

import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
BASH = os.environ.get("BASH_EXE") or shutil.which("bash")
if os.name == "nt" and "BASH_EXE" not in os.environ:
    git = shutil.which("git")
    candidate = Path(git).parent.parent / "bin/bash.exe" if git else None
    BASH = str(candidate) if candidate and candidate.is_file() else None


@unittest.skipUnless(BASH, "Bash is required for packaging configuration tests")
class PackagingTests(unittest.TestCase):
    def run_script(self, **settings):
        env = {key: value for key, value in os.environ.items() if key not in {
            "APKTOOL_JAR", "ANDROID_BUILD_TOOLS", "ANDROID_SDK_ROOT",
            "SIGNING_KEY", "SIGNING_CERT", "SIGNING_CERT_SHA256",
        }}
        env.update(settings)
        return subprocess.run(
            [BASH, "--noprofile", "--norc", str(ROOT / "build.sh")],
            env=env, capture_output=True, text=True, timeout=15,
        )

    def test_requires_explicit_apktool(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Set APKTOOL_JAR", result.stderr)

    def test_rejects_invalid_certificate_digest(self):
        result = self.run_script(
            APKTOOL_JAR="missing/apktool.jar", ANDROID_BUILD_TOOLS="missing/tools",
            SIGNING_KEY="missing/key.pk8", SIGNING_CERT="missing/cert.pem",
            SIGNING_CERT_SHA256="invalid",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain 64 hexadecimal digits", result.stderr)

    def test_checks_explicit_tools_without_sdk_root(self):
        result = self.run_script(
            APKTOOL_JAR="missing/apktool.jar", ANDROID_BUILD_TOOLS="missing/tools",
            SIGNING_KEY="missing/key.pk8", SIGNING_CERT="missing/cert.pem",
            SIGNING_CERT_SHA256="A" * 64,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing build dependency: missing/apktool.jar", result.stderr)


if __name__ == "__main__":
    unittest.main()
