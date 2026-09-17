import io
import os
import secrets
import shutil
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import cv2
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from flask import Flask, abort, redirect, request, send_file, session

STATE = Path(os.getenv("CCTV_STATE_DIR", "/var/lib/cctv"))
DB, PHOTOS = STATE / "config.db", STATE / "photos"
KEY = os.environ["CCTV_PHOTO_KEY"].encode()
INTERVAL = max(5, int(os.getenv("CCTV_CAPTURE_INTERVAL", "60")))
MODEL, DEVICE_ID = os.getenv("CCTV_MODEL", "CCTV-1"), os.environ["CCTV_DEVICE_ID"]
VERSION = Path(os.getenv("CCTV_VERSION_FILE", "/opt/cctv/current/VERSION"))
FACTORY_PASSWORD = os.getenv("CCTV_FACTORY_INITIAL_PASSWORD", "")

ph, fernet = PasswordHasher(), Fernet(KEY)
capture_lock = threading.Lock()
app = Flask(__name__)
app.secret_key = os.environ["CCTV_SESSION_SECRET"]


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def get(name, default=""):
    with db() as con:
        row = con.execute("SELECT value FROM settings WHERE name=?", (name,)).fetchone()
    return row["value"] if row else default


def put(name, value):
    with db() as con:
        con.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (name, value))


def app_version():
    return VERSION.read_text().strip() if VERSION.exists() else "development"


def set_admin_password(con, password, must_change):
    if len(password) < 8:
        raise RuntimeError("初期パスワードは8文字以上にしてください")
    con.execute("INSERT OR REPLACE INTO settings VALUES ('admin_hash',?)", (ph.hash(password),))
    con.execute("INSERT OR REPLACE INTO settings VALUES ('configured','1')")
    con.execute("INSERT OR REPLACE INTO settings VALUES ('must_change',?)", ("1" if must_change else "0",))


def restore_factory_state(con):
    set_admin_password(con, FACTORY_PASSWORD, must_change=True)
    con.execute("INSERT OR REPLACE INTO settings VALUES ('capture_enabled','0')")
    con.execute("INSERT OR REPLACE INTO settings VALUES ('last_capture','')")
    con.execute("INSERT OR REPLACE INTO settings VALUES ('last_capture_error','')")


def init(password=None):
    STATE.mkdir(parents=True, exist_ok=True)
    PHOTOS.mkdir(mode=0o700, exist_ok=True)
    with db() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS photos(id TEXT PRIMARY KEY,taken_at TEXT,path TEXT);
            CREATE TABLE IF NOT EXISTS failures(ip TEXT PRIMARY KEY,count INTEGER,until REAL);
            CREATE TABLE IF NOT EXISTS updates(
                attempted_at TEXT, previous_version TEXT, target_version TEXT,
                manifest_sha256 TEXT, bundle_sha256 TEXT, source_url TEXT,
                verification TEXT, detail TEXT
            );
        """)
        configured = con.execute("SELECT value FROM settings WHERE name='configured'").fetchone()
        if password:
            set_admin_password(con, password, must_change=True)
            con.execute("INSERT OR REPLACE INTO settings VALUES ('capture_enabled','0')")
        elif not configured or configured["value"] != "1":
            restore_factory_state(con)
        elif not con.execute("SELECT 1 FROM settings WHERE name='capture_enabled'").fetchone():
            con.execute("INSERT INTO settings VALUES ('capture_enabled','1')")


def admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect("/login")
        if get("must_change") == "1" and request.path != "/password":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def csrf(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.form.get("csrf") != session.get("csrf"):
            abort(400)
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def reject_api_before_initial_password_change():
    if request.path.startswith("/api/") and get("must_change") == "1":
        abort(403)


def capture():
    with capture_lock:
        if get("capture_enabled", "1") != "1":
            return
        camera = cv2.VideoCapture(0)
        try:
            if not camera.isOpened():
                raise RuntimeError("USBカメラを開けません")
            ok, frame = camera.read()
            if not ok:
                raise RuntimeError("USBカメラから画像を取得できません")
            ok, encoded = cv2.imencode(".jpg", frame)
            if not ok:
                raise RuntimeError("画像をJPEGへ変換できません")
            image_id = str(uuid.uuid4())
            path = PHOTOS / (str(uuid.uuid4()) + ".bin")
            path.write_bytes(fernet.encrypt(encoded.tobytes()))
            path.chmod(0o600)
            with db() as con:
                con.execute("INSERT INTO photos VALUES (?,?,?)", (image_id, utcnow(), str(path)))
            put("last_capture", utcnow())
            put("last_capture_error", "")
        finally:
            camera.release()


def capture_loop():
    while True:
        try:
            capture()
        except Exception as error:
            put("last_capture_error", str(error)[:200])
        time.sleep(INTERVAL)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/version")
def version_api():
    return {"model": MODEL, "device_id": DEVICE_ID, "version": app_version()}


@app.get("/api/latest")
@admin
def latest_api():
    with db() as con:
        latest = con.execute("SELECT id,taken_at FROM photos ORDER BY taken_at DESC LIMIT 1").fetchone()
    return {"image": {"id": latest["id"], "taken_at": latest["taken_at"]} if latest else None, "last_capture": get("last_capture"), "last_capture_error": get("last_capture_error")}


@app.route("/login", methods=["GET", "POST"])
def login():
    if get("configured") != "1":
        return "未設定です．ローカル管理コマンドで管理者を設定してください．", 503
    if request.method == "POST":
        ip, password = request.remote_addr or "unknown", request.form.get("password", "")
        with db() as con:
            failed = con.execute("SELECT * FROM failures WHERE ip=?", (ip,)).fetchone()
            if failed and failed["until"] > time.time():
                return "ログインを一時停止しています", 429
            try:
                valid = ph.verify(get("admin_hash"), password)
            except Exception:
                valid = False
            if valid:
                con.execute("DELETE FROM failures WHERE ip=?", (ip,))
                session.clear()
                session.update(admin=True, csrf=secrets.token_urlsafe(32), must_change=(get("must_change") == "1"))
                return redirect("/password" if session["must_change"] else "/")
            count = (failed["count"] if failed else 0) + 1
            con.execute("INSERT OR REPLACE INTO failures VALUES (?,?,?)", (ip, count, time.time() + 300 if count >= 5 else 0))
        return "ログインに失敗しました", 401
    return "<form method=post><input type=password name=password required><button>ログイン</button></form>"


@app.get("/")
@admin
def index():
    with db() as con:
        latest = con.execute("SELECT id,taken_at FROM photos ORDER BY taken_at DESC LIMIT 1").fetchone()
    token = session["csrf"]
    latest_view = f'<img id=latest-image src="/images/{latest["id"]}?v={latest["taken_at"]}" alt="最新画像">' if latest else '<p id=no-image>まだ画像がありません</p>'
    return f'''<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>CCTV</title><style>:root{{font-family:system-ui,sans-serif;color:#17202a;background:#eef2f6}}body{{margin:0}}header{{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 5vw;background:#102a43;color:#fff}}header small{{display:block;margin-top:3px}}.logout{{color:#fff}}button,input{{font:inherit;box-sizing:border-box}}.menu-button{{border:1px solid #d9e2ec;border-radius:8px;padding:8px 14px;background:transparent;color:#fff;cursor:pointer}}main{{width:min(1100px,92vw);margin:24px auto}}.card{{background:#fff;border-radius:16px;padding:22px;box-shadow:0 6px 22px #102a4318}}.camera{{text-align:center}}#image-container{{min-height:min(52vh,520px);display:grid;place-items:center}}#latest-image{{display:block;max-width:100%;max-height:68vh;margin:12px auto;border-radius:10px;background:#202b36}}.status{{display:flex;justify-content:center;gap:10px;flex-wrap:wrap}}.tag{{background:#d9f1e5;color:#17633b;border-radius:999px;padding:6px 11px;font-size:.85rem}}.error{{display:none;margin-top:14px;color:#9b1c1c;background:#fde8e8;border-radius:8px;padding:10px;text-align:left}}.error.visible{{display:block}}#admin-menu{{position:fixed;top:70px;right:4vw;z-index:10;width:min(380px,92vw)}}.menu-card{{border-top:1px solid #d9e2ec;padding-top:16px;margin-top:16px}}.menu-card:first-child{{border:0;padding:0;margin:0}}input,.primary,.danger{{width:100%;margin-top:8px;padding:11px;border-radius:8px;border:1px solid #cbd5df}}.primary,.danger{{border:0;color:#fff;font-weight:700;cursor:pointer}}.primary{{background:#146c94}}.danger{{background:#b42318}}</style><header><div><strong>CCTV</strong><small>型番: {MODEL}　個体ID: {DEVICE_ID}　ソフトウェア版: {app_version()}</small></div><div><button type=button class=menu-button onclick=toggleMenu()>メニュー</button> <a class=logout href=/logout>ログアウト</a></div></header><main><section class="card camera"><h1>最新画像</h1><div id=image-container>{latest_view}</div><p id=taken-at>{'撮影時刻: '+latest['taken_at'] if latest else '撮影時刻: 未実行'}</p><div class=status><span class=tag id=capture-state>撮影待機中</span><span class=tag id=last-capture>最終撮影: {get('last_capture','未実行')}</span></div><p id=capture-error class=error></p></section></main><aside id=admin-menu class=card hidden><section class=menu-card><h2>パスワード変更</h2><form method=post action=/password><input type=hidden name=csrf value="{token}"><input type=password minlength=8 name=password required placeholder="新しいパスワード"><button class=primary>変更</button></form></section><section class=menu-card><h2>初期化</h2><p>保存画像，設定，認証情報を削除します．</p><form method=post action=/reset><input type=hidden name=csrf value="{token}"><button class=danger>初期化</button></form></section></aside><script>function toggleMenu(){{const m=document.getElementById('admin-menu');m.hidden=!m.hidden}}function showImage(d){{let i=document.getElementById('latest-image');if(!i){{i=document.createElement('img');i.id='latest-image';i.alt='最新画像';document.getElementById('image-container').replaceChildren(i)}}if(i.dataset.imageId!==d.id){{i.src='/images/'+d.id+'?v='+encodeURIComponent(d.taken_at);i.dataset.imageId=d.id}}document.getElementById('taken-at').textContent='撮影時刻: '+d.taken_at;document.getElementById('capture-state').textContent='撮影中'}}async function refreshLatestImage(){{try{{const r=await fetch('/api/latest',{{cache:'no-store'}});if(!r.ok)throw new Error();const d=await r.json();document.getElementById('last-capture').textContent='最終撮影: '+(d.last_capture||'未実行');const e=document.getElementById('capture-error');e.textContent=d.last_capture_error?'撮影エラー: '+d.last_capture_error:'';e.classList.toggle('visible',Boolean(d.last_capture_error));if(d.image)showImage(d.image);else document.getElementById('capture-state').textContent=d.last_capture_error?'撮影エラー':'画像を待機中'}}catch(_){{document.getElementById('capture-state').textContent='画面更新エラー'}}}}refreshLatestImage();window.setInterval(refreshLatestImage,5000);</script>'''


@app.route("/password", methods=["GET", "POST"])
@admin
def change_password():
    if request.method == "GET":
        title = "初期パスワードの変更" if get("must_change") == "1" else "パスワード変更"
        return f'<h1>{title}</h1><form method=post><input type=hidden name=csrf value="{session["csrf"]}"><input type=password minlength=8 name=password required><button>変更</button></form>'
    if request.form.get("csrf") != session.get("csrf"):
        abort(400)
    password = request.form.get("password", "")
    if len(password) < 8:
        abort(400)
    put("admin_hash", ph.hash(password))
    put("must_change", "0")
    put("capture_enabled", "1")
    session["must_change"] = False
    return redirect("/")


@app.get("/images/<image_id>")
@admin
def image(image_id):
    with db() as con:
        row = con.execute("SELECT path FROM photos WHERE id=?", (image_id,)).fetchone()
    if not row:
        abort(404)
    return send_file(io.BytesIO(fernet.decrypt(Path(row["path"]).read_bytes())), mimetype="image/jpeg", max_age=0)


@app.get("/api/status")
@admin
def status():
    with db() as con:
        count = con.execute("SELECT count(*) FROM photos").fetchone()[0]
    return {"last_capture": get("last_capture"), "last_capture_error": get("last_capture_error"), "photo_count": count, "encrypted_storage": True}


@app.get("/api/update/status")
@admin
def update_status():
    with db() as con:
        row = con.execute("SELECT * FROM updates ORDER BY rowid DESC LIMIT 1").fetchone()
    return dict(row) if row else {"verification": "not_run"}


@app.post("/reset")
@admin
@csrf
def reset():
    with capture_lock:
        shutil.rmtree(PHOTOS, ignore_errors=True)
        PHOTOS.mkdir(mode=0o700)
        with db() as con:
            con.execute("DELETE FROM photos")
            con.execute("DELETE FROM failures")
            con.execute("DELETE FROM settings")
            restore_factory_state(con)
    session.clear()
    return redirect("/login")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    password = os.getenv("CCTV_ADMIN_PASSWORD")
    if len(os.sys.argv) > 1 and os.sys.argv[1] == "init":
        if not password or len(password) < 8:
            raise SystemExit("CCTV_ADMIN_PASSWORDは8文字以上にしてください")
        init(password)
        print("管理者パスワードを設定しました")
    else:
        init()
        threading.Thread(target=capture_loop, daemon=True).start()
        app.run("0.0.0.0", 443, ssl_context=(os.getenv("CCTV_TLS_CERT", "/etc/cctv/tls/cctv.crt"), os.getenv("CCTV_TLS_KEY", "/etc/cctv/tls/cctv.key")), threaded=True)
