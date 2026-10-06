#!/usr/bin/env python3
"""Rebuild this catalog from AERA's, served from our forks of their plugins.

Verifies AERA's signed catalog, fast-forwards each fork, mirrors each release package
the catalog names into the fork (checked against the catalog's size and SHA-256),
points the entries at the forks and signs the result with our key. Plugins listed in
forks.json "exclude" are left out; "own" carries entries for forks we change, which
take the place of AERA's.

    scripts/sync_forks.py --key PRIVATE_KEY [--dry-run] [--push]
"""

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM_KEY = ROOT / "keys/catalog-public.pem"
OWN_KEY = ROOT / "keys/yogi-catalog-public.pem"
UPSTREAM_RAW = "https://raw.githubusercontent.com/AERA-Plugins/registry/main/"
RAW = re.compile(r"https://raw\.githubusercontent\.com/AERA-Plugins/([^/]+)/([0-9a-f]{40})/(.+)\Z")
RELEASE = re.compile(r"https://github\.com/AERA-Plugins/([^/]+)/releases/download/([^/]+)/([^/]+)\Z")


def fetch(url, limit=600 * 1024 * 1024):
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{url} is larger than {limit} bytes")
    return data


def openssl_verify(content, signature_hex, public_key):
    with tempfile.TemporaryDirectory() as directory:
        body, raw = Path(directory) / "body", Path(directory) / "sig"
        body.write_bytes(content)
        raw.write_bytes(bytes.fromhex(signature_hex.strip()))
        subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                        "-inkey", str(public_key), "-in", str(body), "-sigfile", str(raw)],
                       check=True, stdout=subprocess.DEVNULL)


def openssl_sign(content, private_key):
    with tempfile.TemporaryDirectory() as directory:
        body, raw = Path(directory) / "body", Path(directory) / "sig"
        body.write_bytes(content)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
                        "-in", str(body), "-out", str(raw)], check=True)
        return raw.read_bytes().hex() + "\n"


def gh(*arguments, check=True):
    return subprocess.run(["gh", *arguments], check=check, capture_output=True, text=True)


def release_assets(fork, tag):
    result = gh("release", "view", tag, "-R", fork, "--json", "assets", check=False)
    if result.returncode != 0:
        return None
    return {asset["name"]: asset["size"] for asset in json.loads(result.stdout)["assets"]}


def mirror_release(repo, fork, tag, name, size, digest, dry_run):
    assets = release_assets(fork, tag)
    if assets is not None and assets.get(name) == size:
        return "present"
    if dry_run:
        return "would mirror"
    data = fetch(f"https://github.com/AERA-Plugins/{repo}/releases/download/{tag}/{name}", size)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"{repo} {tag} {name} does not match the signed catalog")
    with tempfile.TemporaryDirectory() as directory:
        package = Path(directory) / name
        package.write_bytes(data)
        if assets is None:
            gh("release", "create", tag, "-R", fork, "--verify-tag", "--title", tag,
               "--notes", f"Mirror of AERA-Plugins/{repo} {tag}.", str(package))
        else:
            gh("release", "upload", tag, "-R", fork, "--clobber", str(package))
    return "mirrored"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=Path, required=True, help="our Ed25519 private key")
    parser.add_argument("--dry-run", action="store_true", help="report, change nothing")
    parser.add_argument("--push", action="store_true", help="commit and push the catalog")
    arguments = parser.parse_args()
    config = json.loads((ROOT / "forks.json").read_text())
    owner, prefix = config["owner"], config["prefix"]
    excluded = set(config.get("exclude", []))
    own = {entry["id"]: entry for entry in config.get("own", [])}

    content = fetch(UPSTREAM_RAW + "catalog.json", 1024 * 1024)
    openssl_verify(content, fetch(UPSTREAM_RAW + "catalog.json.sig", 4096).decode("ascii"),
                   UPSTREAM_KEY)
    upstream = json.loads(content)
    print(f"AERA catalog {upstream['generated']}: {len(upstream['plugins'])} plugins, signature good")

    plugins = []
    for entry in upstream["plugins"]:
        plugin_id = entry["id"]
        if plugin_id in excluded:
            print(f"  {plugin_id}: excluded")
            continue
        if plugin_id in own:
            plugins.append(own.pop(plugin_id))
            print(f"  {plugin_id}: ours")
            continue
        release = RELEASE.match(entry["package_url"])
        manifest = RAW.match(entry["manifest_url"])
        signature = RAW.match(entry["signature_url"])
        if not (release and manifest and signature):
            raise ValueError(f"{plugin_id}: unexpected URL layout")
        repo, tag, name = release.groups()
        fork = f"{owner}/{prefix}{repo}"
        if not arguments.dry_run:
            gh("repo", "sync", fork, "--source", f"AERA-Plugins/{repo}", "--branch", "main")
        state = mirror_release(repo, fork, tag, name, entry["package_size"],
                               entry["package_sha256"], arguments.dry_run)
        moved = dict(entry)
        for key, match in (("manifest_url", manifest), ("signature_url", signature)):
            ref, path = match.group(2), match.group(3)
            moved[key] = f"https://raw.githubusercontent.com/{fork}/{ref}/{path}"
            if fetch(moved[key], 64 * 1024) != fetch(entry[key], 64 * 1024):
                raise ValueError(f"{plugin_id}: {moved[key]} differs from AERA's")
        moved["package_url"] = f"https://github.com/{fork}/releases/download/{tag}/{name}"
        plugins.append(moved)
        print(f"  {plugin_id} {entry['version']}: {state}")
    plugins.extend(own.values())

    catalog = {"schema": 1,
               "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "plugins": plugins}
    text = (json.dumps(catalog, indent=2, ensure_ascii=False) + "\n").encode()
    if arguments.dry_run:
        print(f"dry run: catalog would list {len(plugins)} plugins")
        return 0
    signature_hex = openssl_sign(text, arguments.key)
    openssl_verify(text, signature_hex, OWN_KEY)
    (ROOT / "catalog.json").write_bytes(text)
    (ROOT / "catalog.json.sig").write_text(signature_hex)
    print(f"signed catalog with {len(plugins)} plugins")
    if arguments.push:
        subprocess.run(["git", "-C", str(ROOT), "add", "catalog.json", "catalog.json.sig"], check=True)
        if subprocess.run(["git", "-C", str(ROOT), "diff", "--cached", "--quiet"]).returncode:
            subprocess.run(["git", "-C", str(ROOT), "commit", "-q", "-m",
                            f"catalog: sync from AERA's {upstream['generated']}"], check=True)
            subprocess.run(["git", "-C", str(ROOT), "push", "-q", "origin", "main"], check=True)
            print("pushed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
