"""rootで実行する署名付きCCTV更新処理．"""
import base64
import hashlib
import io
import json
import os
import sqlite3
import ssl
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE_URL = os.environ["CCTV_UPDATE_URL"].rstrip("/")
PUBLIC_KEY = Path(os.getenv("CCTV_UPDATE_PUBLIC_KEY", "/etc/cctv/update-public.key"))
CA_CERT = os.getenv("CCTV_UPDATE_CA_CERT", "")
STATE = Path(os.getenv("CCTV_STATE_DIR", "/var/lib/cctv"))
DB = STATE / "config.db"
RELEASES, CURRENT = Path("/opt/cctv/releases"), Path("/opt/cctv/current")


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def current_version():
    version = CURRENT / "VERSION"
    return version.read_text().strip() if version.exists() else "unknown"


def download(name):
    context = ssl.create_default_context(cafile=CA_CERT or None)
    with urllib.request.urlopen(f"{BASE_URL}/{name}", timeout=30, context=context) as response:
        return response.read()


def record(previous, target, manifest_hash, bundle_hash, verification, detail):
    STATE.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS updates(
                attempted_at TEXT, previous_version TEXT, target_version TEXT,
                manifest_sha256 TEXT, bundle_sha256 TEXT, source_url TEXT,
                verification TEXT, detail TEXT
            )
        """)
        con.execute("INSERT INTO updates VALUES (?,?,?,?,?,?,?,?)", (
            utcnow(), previous, target, manifest_hash, bundle_hash,
            BASE_URL, verification, detail[:500],
        ))


def extract_safely(bundle, destination):
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
        for entry in archive.getmembers():
            resolved = (destination / entry.name).resolve()
            if not str(resolved).startswith(str(destination.resolve()) + os.sep):
                raise RuntimeError("不正な更新パスです")
            if entry.issym() or entry.islnk() or not (entry.isdir() or entry.isfile()):
                raise RuntimeError("リンク又は特殊ファイルを含む更新物です")
        archive.extractall(destination, filter="data")


def main():
    previous, target, manifest_hash, bundle_hash = current_version(), "unknown", "", ""
    try:
        manifest_bytes = download("manifest.json")
        signature = base64.b64decode(download("manifest.sig"), validate=True)
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(PUBLIC_KEY.read_text().strip(), validate=True)
        )
        key.verify(signature, manifest_bytes)
        manifest = json.loads(manifest_bytes)
        target = manifest["version"]
        if not target.replace(".", "").isdigit():
            raise RuntimeError("不正な版番号です")
        bundle = download(manifest["bundle"])
        bundle_hash = hashlib.sha256(bundle).hexdigest()
        if bundle_hash != manifest["sha256"]:
            raise RuntimeError("更新ハッシュが一致しません")
        destination = RELEASES / target
        if destination.exists():
            record(previous, target, manifest_hash, bundle_hash, "already_installed", "対象版は既に存在します")
            return
        RELEASES.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=RELEASES) as temporary:
            stage = Path(temporary) / target
            stage.mkdir()
            extract_safely(bundle, stage)
            version_file = stage / "VERSION"
            if not (stage / "app.py").is_file() or not version_file.is_file():
                raise RuntimeError("更新物が不完全です")
            if version_file.read_text().strip() != target:
                raise RuntimeError("manifestとVERSIONの版番号が一致しません")
            stage.rename(destination)
        new_link = RELEASES / ".new-current"
        new_link.symlink_to(destination)
        new_link.replace(CURRENT)
        if current_version() != target:
            raise RuntimeError("currentリンクの切替後に版番号を確認できません")
        record(previous, target, manifest_hash, bundle_hash, "verified_and_installed", "署名，ハッシュ，版番号を確認済み")
        print(f"検証済み更新を展開しました: {target}")
    except Exception as error:
        record(previous, target, manifest_hash, bundle_hash, "failed", str(error))
        raise


if __name__ == "__main__":
    main()
