"""Writes a hash-pinned requirements.txt: for each pinned package, the sha256 of
every Windows-compatible wheel PyPI has for that exact version.
Usage: python tools/hash_requirements.py requirements.txt
Edit the versions in requirements.txt first; this replaces the --hash lines."""
import json
import re
import sys
import urllib.request
from pathlib import Path

HEADER = """\
# Tray app (Windows 10/11, Python 3.10+). build_feed.py needs only the standard library.
#
# Every package is pinned to the version the app was tested with (Nov 2026), including
# the dependencies pulled in by the three direct ones. Each pin also lists the SHA-256
# fingerprint of every Windows build of that version, as published on PyPI, so pip
# refuses any download that doesn't match exactly (install.ps1 also allows ready-built
# packages only, so nothing is compiled from source).
#
# To upgrade a package: change its version, run "python tools/hash_requirements.py
# requirements.txt" to refresh the --hash lines from PyPI, then test before committing.
"""

DIRECT = {"pillow", "pystray", "windows-toasts"}


def windows_wheel(name):
    if not name.endswith(".whl"):
        return False  # skip source archives: never build from source
    platform = name[:-4].split("-")[-1]
    return platform == "any" or platform.startswith("win")


def main(path):
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s#]+)", Path(path).read_text(encoding="utf-8"), re.M)
    blocks = {"direct": [], "deps": []}
    for name, version in pins:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as r:
            files = json.load(r)["urls"]
        hashes = sorted({f["digests"]["sha256"] for f in files if windows_wheel(f["filename"])})
        if not hashes:
            raise SystemExit(f"no Windows wheels for {name}=={version}")
        lines = [f"{name}=={version}"] + [f"    --hash=sha256:{h}" for h in hashes]
        blocks["direct" if name.lower() in DIRECT else "deps"].append(" \\\n".join(lines))
        print(f"{name}=={version}: {len(hashes)} Windows builds")
    out = (HEADER + "\n# direct\n" + "\n".join(blocks["direct"])
           + "\n\n# pulled in by the above\n" + "\n".join(blocks["deps"]) + "\n")
    Path(path).write_text(out, encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1])
