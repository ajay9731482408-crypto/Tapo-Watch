"""
Tapo Watch v2 - secure live view, motion + face detection, recording,
event log with snapshots, Telegram alerts, arm schedule, auto-delete.
Run:  pip install -r requirements.txt && python app.py   ->  http://localhost:5000
"""
import os, re, time, json, glob, secrets, threading, shutil, subprocess, base64, hmac, struct, ipaddress
from collections import deque
from datetime import datetime, timedelta, date
from urllib.parse import urlparse
from urllib.parse import quote
import cv2
import numpy as np
from flask import (Flask, Response, jsonify, request, session, redirect,
                   send_from_directory, render_template_string)
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
REC, SNAP = os.path.join(BASE, "recordings"), os.path.join(BASE, "snaps")
SETF, EVF = os.path.join(BASE, "settings.json"), os.path.join(BASE, "events.json")
os.makedirs(REC, exist_ok=True); os.makedirs(SNAP, exist_ok=True)

D = {"cams": [], "sensitivity": 60, "detect_faces": True, "show_boxes": True, "enhance": False,
     "record": True, "post_roll": 5, "cooldown": 30,
     "schedule_on": False, "arm_from": "22:00", "arm_to": "06:00",
     "auto_delete": True, "delete_time": "03:00", "delete_every": 1, "keep_days": 0, "max_gb": 20, "last_delete": "",
     "cloud_on": False, "cloud_remote": "", "cloud_path": "TapoWatch", "cloud_delete_local": False,
     "tg_token": "", "tg_chat": "", "alarm_on_event": False, "alarm_trigger": "face", "alarm_secs": 10,
     "lan_only": True, "offline_alert": True, "restore_outage": True, "totp": "", "pw_hash": "", "secret": ""}
SECRET_KEYS = ("pw_hash", "secret", "tg_token")
S = dict(D)
if os.path.exists(SETF):
    S.update(json.load(open(SETF)))
if not S["secret"]:
    S["secret"] = secrets.token_hex(32)
def save():
    with open(SETF, "w") as f: json.dump(S, f)
    try: os.chmod(SETF, 0o600)  # only your user can read the camera passwords
    except OSError: pass
save()
events = json.load(open(EVF)) if os.path.exists(EVF) else []

app = Flask(__name__)
app.secret_key = S["secret"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=12))
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
lock, fails = threading.Lock(), {}
clahe = cv2.createCLAHE(2.0, (8, 8))
cams, tapos = {}, {}   # cid -> runtime state / pytapo client
NIGHT = {"auto": "auto", "day": "off", "night": "on"}

def migrate():
    if not S["cams"] and S.get("cam_ip"):  # older single-camera settings
        S["cams"].append({"id": "cam1", "name": "Camera 1", "ip": S["cam_ip"], "user": S.get("cam_user", ""),
                          "pass": S.get("cam_pass", ""), "stream": S.get("stream", "stream1"), "track": False, "night": "auto"})
        save()

def cfg(cid): return next((c for c in S["cams"] if c["id"] == cid), None)

def armed():
    if not S["schedule_on"]: return True
    n, a, b = datetime.now().strftime("%H:%M"), S["arm_from"], S["arm_to"]
    return a <= n < b if a <= b else (n >= a or n < b)

BRANDS = {"tapo": "Tapo", "cpplus": "CP Plus / Dahua", "cpplus2": "CP Plus (older, port 5543)",
          "hikvision": "Hikvision", "reolink": "Reolink", "custom": "Other (RTSP address)"}
TAPO = {"privacy": "setPrivacyMode", "led": "setLEDEnabled", "person": "setPersonDetection",
        "tamper": "setTamperDetection", "flip": "setImageFlipVertical"}

def rtsp_url(c):
    """Video address for each brand. Special characters in logins are escaped."""
    u, p, hq = quote(c["user"], safe=""), quote(c["pass"], safe=""), c.get("stream") != "stream2"
    b = c.get("brand", "tapo")
    if b == "custom": return c["url"].replace("{user}", u).replace("{pass}", p)
    path = {"tapo": f"554/{'stream1' if hq else 'stream2'}",
            "cpplus": f"554/cam/realmonitor?channel=1&subtype={0 if hq else 1}",
            "cpplus2": "5543/live/channel1",
            "hikvision": f"554/Streaming/Channels/{101 if hq else 102}",
            "reolink": f"554/h264Preview_01_{'main' if hq else 'sub'}"}[b]
    return f"rtsp://{u}:{p}@{c['ip']}:{path}"

def clean_name(n): return re.sub(r"[<>\"'&]", "", str(n)).strip()[:40]

def validate_cam(c):
    if c.get("brand", "tapo") not in BRANDS: return "Unknown camera brand."
    if c.get("brand") == "custom":
        if not re.match(r"^(rtsp|http|https)://", c.get("url", "")): return "Enter a full address starting with rtsp://"
    elif c.get("ip") and not re.match(r"^[A-Za-z0-9.\-:]+$", c["ip"]): return "That address has characters a camera address can't have."
    return None

PROBE = {"motor": "getMotorCapability", "presets": "getPresets", "privacy": "getPrivacyMode",
         "motion": "getMotionDetection", "person": "getPersonDetection", "pet": "getPetDetection"}

def detect(cid):
    """Ask a Tapo camera which features it supports (best effort; depends on model and firmware)."""
    info = cam_call(cid, "getBasicInfo")
    model = (((info or {}).get("device_info") or {}).get("basic_info") or {}).get("device_model", "")
    f = {"model": model}
    for k, fn in PROBE.items():
        try: cam_call(cid, fn); f[k] = True
        except Exception: f[k] = False
    return f

def restore(cid):
    """After a power cut or reboot: put the camera back the way you left it."""
    c = cfg(cid)
    if not c or c.get("brand", "tapo") != "tapo": return
    time.sleep(3)
    try:
        if "features" not in c: c["features"] = detect(cid); save()
        if S["restore_outage"]:
            cam_call(cid, "setDayNightMode", NIGHT.get(c.get("night", "auto"), "auto"))
            for k, v in (c.get("opts") or {}).items(): cam_call(cid, TAPO[k], v)
            if c.get("track"): cam_call(cid, "setAutoTrackTarget", True)
            note(f"Camera settings restored: {c['name']}")
    except Exception as e:
        print("restore skipped:", e)

def adjust(f, a):
    """Picture adjustments: rotate, mirror, brightness, contrast, colour."""
    r = a.get("rot", 0)
    if r: f = cv2.rotate(f, {90: cv2.ROTATE_90_CLOCKWISE, 180: cv2.ROTATE_180, 270: cv2.ROTATE_90_COUNTERCLOCKWISE}[r])
    if a.get("mirror"): f = cv2.flip(f, 1)
    al, be = a.get("contrast", 100) / 100, a.get("bright", 0)
    if al != 1 or be: f = cv2.convertScaleAbs(f, alpha=al, beta=be)
    sat = a.get("sat", 100) / 100
    if sat != 1:
        hsv = cv2.cvtColor(f, cv2.COLOR_BGR2HSV).astype("float32")
        hsv[..., 1] = np.clip(hsv[..., 1] * sat, 0, 255)
        f = cv2.cvtColor(hsv.astype("uint8"), cv2.COLOR_HSV2BGR)
    return f

def follow_view(st, frame, boxes, w, h, now):
    """Digital tracking for cameras that can't move: smoothly zoom in on whatever is moving."""
    z = st.setdefault("z", [0.0, 0.0, float(w), float(h)])
    if boxes:
        x1, y1 = min(b[0] for b in boxes), min(b[1] for b in boxes)
        x2, y2 = max(b[0] + b[2] for b in boxes), max(b[1] + b[3] for b in boxes)
        cw = min(w, max(w / 3, (x2 - x1) * 2.2, (y2 - y1) * 2.2 * w / h)); ch = cw * h / w
        t = (min(max((x1 + x2) / 2 - cw / 2, 0), w - cw), min(max((y1 + y2) / 2 - ch / 2, 0), h - ch), cw, ch)
        st["hold"] = now
    elif now - st.get("hold", 0) > 3: t = (0, 0, w, h)
    else: t = z
    z[:] = [z[i] + (t[i] - z[i]) * .15 for i in range(4)]
    x, y, cw, ch = int(z[0]), int(z[1]), max(int(z[2]), 16), max(int(z[3]), 9)
    return cv2.resize(frame[y:y + ch, x:x + cw], (w, h))

def telegram(text, path=None):
    if not (S["tg_token"] and S["tg_chat"]): return
    try:
        import requests
        base = f"https://api.telegram.org/bot{S['tg_token']}"
        if path: requests.post(base + "/sendPhoto", data={"chat_id": S["tg_chat"], "caption": text}, files={"photo": open(path, "rb")}, timeout=15)
        else: requests.post(base + "/sendMessage", data={"chat_id": S["tg_chat"], "text": text}, timeout=15)
    except Exception as e:
        print("alert failed:", e)

def cam_call(cid, fn, *a):
    """Camera control API (pytapo): night vision, auto-tracking, siren."""
    c = cfg(cid)
    try:
        if cid not in tapos:
            from pytapo import Tapo
            tapos[cid] = Tapo(c["ip"], c["user"], c["pass"])
        return getattr(tapos[cid], fn)(*a)
    except Exception:
        tapos.pop(cid, None); raise

def siren(cid, on):
    cam_call(cid, "startManualAlarm" if on else "stopManualAlarm")
    cams[cid]["siren"] = on

def siren_auto(cid):
    try:
        siren(cid, True); time.sleep(S["alarm_secs"]); siren(cid, False)
    except Exception as e:
        print("siren failed:", e)
        if cid in cams: cams[cid]["siren"] = False

def cloud_ok(): return bool(S["cloud_on"] and S["cloud_remote"] and shutil.which("rclone"))
def cloud_dest(): return f"{S['cloud_remote']}:{S['cloud_path']}"

def cloud_upload(path):
    if not cloud_ok(): return
    r = subprocess.run(["rclone", "copy", path, cloud_dest()], capture_output=True)
    if r.returncode == 0 and S["cloud_delete_local"]:
        try: os.remove(path)
        except OSError: pass

def trigger(cid, kind, frame):
    st, now = cams[cid], time.time()
    if now - st["last_evt"] < S["cooldown"]: return
    st["last_evt"] = now
    name = f"{cid}_{datetime.now():%Y-%m-%d_%H-%M-%S}.jpg"
    path = os.path.join(SNAP, name)
    cv2.imwrite(path, frame)
    events.insert(0, {"t": datetime.now().isoformat(timespec="seconds"), "kind": kind, "snap": name, "cam": cid})
    del events[300:]
    json.dump(events, open(EVF, "w"))
    if S["tg_token"] and S["tg_chat"]:
        txt = f"{cfg(cid)['name']}: {'Face' if kind == 'face' else 'Motion'} detected {datetime.now():%H:%M:%S}"
        threading.Thread(target=telegram, args=(txt, path), daemon=True).start()
    if S["alarm_on_event"] and not st["siren"] and (kind == "face" or S["alarm_trigger"] == "any"):
        st["siren"] = True
        threading.Thread(target=siren_auto, args=(cid,), daemon=True).start()

def camera_loop(cid):
    st = cams[cid]
    cap, writer, wpath, last_motion, last_face, faces = None, None, None, 0, 0, []
    off_since, off_alerted, was_on, wstart = None, False, False, 0
    bg = cv2.createBackgroundSubtractorMOG2(history=300, varThreshold=32, detectShadows=False)
    while True:
        c = cfg(cid)
        if c is None:  # camera was removed
            if writer: writer.release()
            if cap: cap.release()
            cams.pop(cid, None); return
        if st.pop("reconnect", False) and cap: cap.release(); cap = None
        if not st["online"]:  # tamper / power-cut alert
            was_on = False
            off_since = off_since or time.time()
            if S["offline_alert"] and st.get("seen") and not off_alerted and time.time() - off_since > 60:
                off_alerted = True; note(f"{c['name']} went offline")
                threading.Thread(target=telegram, args=(f"{c['name']} went offline. Check its power, Wi-Fi, or whether it was tampered with.",), daemon=True).start()
        else:
            if not was_on:  # first connection, or back after an outage
                was_on = True
                threading.Thread(target=restore, args=(cid,), daemon=True).start()
            if off_alerted:
                note(f"{c['name']} back online after {int((time.time() - off_since) / 60)} min")
                threading.Thread(target=telegram, args=(f"{c['name']} is back online.",), daemon=True).start()
            off_since, off_alerted = None, False
        if cap is None or not cap.isOpened():
            if not (c["ip"] or c.get("url")): st["online"] = False; time.sleep(2); continue
            cap = cv2.VideoCapture(rtsp_url(c), cv2.CAP_FFMPEG)
            if not cap.isOpened(): st["online"] = False; time.sleep(3); continue
        ok, frame = cap.read()
        if not ok: st["online"] = False; cap.release(); cap = None; time.sleep(2); continue
        st["online"] = True; st["seen"] = True
        if S["enhance"]:
            l, a, b = cv2.split(cv2.cvtColor(frame, cv2.COLOR_BGR2LAB))
            frame = cv2.cvtColor(cv2.merge((clahe.apply(l), a, b)), cv2.COLOR_LAB2BGR)
        if c.get("adj"): frame = adjust(frame, c["adj"])
        h, w = frame.shape[:2]
        now = time.time()
        st["armed"] = det = armed()
        moving, boxes = False, []
        if det:
            small = cv2.resize(frame, (w // 3, h // 3))
            mask = bg.apply(cv2.GaussianBlur(small, (11, 11), 0))
            mask = cv2.dilate(cv2.threshold(mask, 200, 255, cv2.THRESH_BINARY)[1], None, iterations=2)
            min_area = 5000 - S["sensitivity"] * 45
            for cn in cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)[0]:
                if cv2.contourArea(cn) * 9 > min_area:
                    moving = True
                    x, y, bw, bh = [v * 3 for v in cv2.boundingRect(cn)]
                    boxes.append((x, y, bw, bh))
                    if S["show_boxes"]:
                        cv2.rectangle(frame, (x, y), (x + bw, y + bh), (75, 184, 242), 2)
            if S["detect_faces"] and now - last_face > 0.25:
                gray = cv2.equalizeHist(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY))
                faces = face_cascade.detectMultiScale(gray, 1.1, 6, minSize=(60, 60)); last_face = now
            elif not S["detect_faces"]: faces = []
            boxes += [tuple(int(v) for v in f) for f in faces]
            if S["show_boxes"]:
                for (x, y, fw, fh) in faces:
                    cv2.rectangle(frame, (x, y), (x + fw, y + fh), (160, 214, 91), 2)
        else:
            faces = []
        st["faces"] = len(faces)
        if moving or len(faces):
            last_motion = now
            trigger(cid, "face" if len(faces) else "motion", frame)
        st["motion"] = now - last_motion < 1.5
        active = det and S["record"] and now - last_motion < S["post_roll"]
        if writer is not None and now - wstart > 300:  # new file every 5 min, so a power cut loses little
            writer.release(); writer = None; st["cur"] = None
            threading.Thread(target=cloud_upload, args=(wpath,), daemon=True).start()
        if active and writer is None:
            wpath = os.path.join(REC, f"{cid}_{datetime.now():%Y-%m-%d_%H-%M-%S}.mp4")
            writer = cv2.VideoWriter(wpath, cv2.VideoWriter_fourcc(*"mp4v"), 15, (w, h)); st["cur"] = wpath; wstart = now
        if writer is not None:
            cv2.putText(frame, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), (10, h - 12),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
            writer.write(frame)
            if not active:
                writer.release(); writer = None; st["cur"] = None
                threading.Thread(target=cloud_upload, args=(wpath,), daemon=True).start()
        st["recording"] = writer is not None
        shown = follow_view(st, frame, boxes, w, h, now) if c.get("follow") else frame
        with lock: st["frame"] = shown

def camera_guard(cid):
    """If a camera thread ever crashes, start it again."""
    while cid in cams:
        try: camera_loop(cid)
        except Exception as e:
            print("camera loop restarted:", e); time.sleep(5)

def start_cam(cid):
    cams[cid] = {"frame": None, "motion": False, "faces": 0, "recording": False, "online": False,
                 "armed": True, "last_evt": 0, "siren": False, "cur": None}
    threading.Thread(target=camera_guard, args=(cid,), daemon=True).start()

def files(): return sorted(glob.glob(os.path.join(REC, "*.mp4")), key=os.path.getmtime)

def due():
    """Date of the next deletion run: repeats every `delete_every` days."""
    if not S["last_delete"]: return date.today()
    return max(date.today(), date.fromisoformat(S["last_delete"]) + timedelta(days=S["delete_every"]))

def cleanup_loop():
    while True:
        now = datetime.now()
        if S["auto_delete"] and now.date() >= due() and now.strftime("%H:%M") >= S["delete_time"]:
            cutoff = time.time() - S["keep_days"] * 86400
            busy = {st.get("cur") for st in list(cams.values())}
            for f in files() + glob.glob(os.path.join(SNAP, "*.jpg")):
                if os.path.getmtime(f) <= cutoff and f not in busy:
                    try: os.remove(f)
                    except OSError: pass
            if cloud_ok():
                subprocess.run(["rclone", "delete", cloud_dest(), "--min-age", f"{max(S['keep_days'] * 24, 1)}h"], capture_output=True)
            S["last_delete"] = now.date().isoformat(); save()
        fl = files()  # storage cap: drop oldest first
        while len(fl) > 1 and sum(os.path.getsize(f) for f in fl) > S["max_gb"] * 1e9:
            try: os.remove(fl.pop(0))
            except OSError: break
        time.sleep(20)

# ---------- auth ----------
audit_log = deque(maxlen=50)
def note(msg):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} system {msg}"
    audit_log.appendleft(line)
    try:
        with open(os.path.join(BASE, "security.log"), "a") as f: f.write(line + "\n")
    except OSError: pass

def audit(msg):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {request.remote_addr} {msg}"
    audit_log.appendleft(line)
    try:
        with open(os.path.join(BASE, "security.log"), "a") as f: f.write(line + "\n")
    except OSError: pass

def totp(secret, t=None):
    c = struct.pack(">Q", int((t or time.time()) // 30))
    h = hmac.new(base64.b32decode(secret), c, "sha1").digest(); o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000:06d}"

def totp_ok(secret, code):
    return bool(secret) and any(hmac.compare_digest(totp(secret, time.time() + d * 30), str(code).strip()) for d in (-1, 0, 1))

def allowed_ip(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return False
    a = getattr(a, "ipv4_mapped", None) or a
    return a.is_private or a.is_loopback or a.is_link_local or a in ipaddress.ip_network("100.64.0.0/10")  # last = Tailscale

hits = {}
@app.before_request
def guard():
    ip = request.remote_addr or ""
    if S["lan_only"] and not allowed_ip(ip): return "Forbidden", 403
    if request.method in ("POST", "DELETE"):  # blocks other websites from sending commands
        o = request.headers.get("Origin")
        if o and urlparse(o).netloc != request.host: return "Forbidden", 403
        if request.path.startswith("/api/") and request.content_length and not request.is_json: return jsonify(error="JSON required"), 415
    if not request.path.startswith(("/live/", "/rec/", "/snap/")):
        q, now = hits.setdefault(ip, deque()), time.time()
        while q and now - q[0] > 60: q.popleft()
        q.append(now)
        if len(q) > 240: return "Too many requests", 429

@app.after_request
def secure_headers(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; media-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"})
    if request.path.startswith("/api/"): r.headers["Cache-Control"] = "no-store"
    return r

@app.before_request
def gate():
    if request.endpoint in ("login", "setup", "static", "manifest", "icon"): return
    if not S["pw_hash"]: return redirect("/setup")
    if not session.get("ok"):
        return (jsonify(error="auth"), 401) if request.path.startswith("/api") else redirect("/login")

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if S["pw_hash"]: return redirect("/login")
    err = ""
    if request.method == "POST":
        p = request.form.get("pw", "")
        if len(p) < 8: err = "Use at least 8 characters."
        elif p != request.form.get("pw2"): err = "Passwords don't match."
        else:
            S["pw_hash"] = generate_password_hash(p); save()
            session["ok"] = 1; session.permanent = True; return redirect("/")
    return render_template_string(AUTH, title="Create your password", err=err, setup=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    ip, err = request.remote_addr, ""
    f = fails.get(ip, [0, 0])
    if request.method == "POST":
        if time.time() < f[1]: err = "Too many attempts. Wait 5 minutes."
        elif check_password_hash(S["pw_hash"], request.form.get("pw", "")) and (not S["totp"] or totp_ok(S["totp"], request.form.get("code", ""))):
            fails.pop(ip, None); session.clear(); session["ok"] = 1; session.permanent = True
            audit("Signed in"); return redirect("/")
        else:
            f[0] += 1
            if f[0] >= 5: f = [0, time.time() + 300]
            fails[ip] = f; err = "Wrong password or code."; audit("Failed sign-in")
    return render_template_string(AUTH, title="Sign in", err=err, setup=False, totp=bool(S["totp"]))

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

@app.route("/api/password", methods=["POST"])
def change_pw():
    d = request.json
    if not check_password_hash(S["pw_hash"], d.get("current", "")): return jsonify(error="Current password is wrong."), 400
    if len(d.get("new", "")) < 8: return jsonify(error="Use at least 8 characters."), 400
    S["pw_hash"] = generate_password_hash(d["new"]); save(); audit("Password changed"); return jsonify(ok=True)

# ---------- api ----------
HIDDEN = ("pw_hash", "secret", "cams", "last_delete", "totp")

def mjpeg(cid):
    while cid in cams:
        with lock: f = cams[cid]["frame"] if cid in cams else None
        if f is None: time.sleep(0.2); continue
        ok, buf = cv2.imencode(".jpg", f, [cv2.IMWRITE_JPEG_QUALITY, 90])
        yield b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + buf.tobytes() + b"\r\n"
        time.sleep(0.04)

@app.route("/live/<cid>")
def live(cid): return Response(mjpeg(cid), mimetype="multipart/x-mixed-replace; boundary=frame")

@app.route("/api/status")
def status():
    fl = files()
    keys = ("online", "motion", "faces", "recording", "armed", "siren")
    return jsonify(cams={k: {x: v[x] for x in keys} for k, v in list(cams.items())},
                   used_mb=round(sum(os.path.getsize(f) for f in fl) / 1e6), clips=len(fl),
                   next_delete=f"{due().isoformat()} {S['delete_time']}" if S["auto_delete"] else None,
                   cloud=cloud_ok(), cloud_wanted=S["cloud_on"], rclone=bool(shutil.which("rclone")))

@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        for k, v in request.json.items():
            if k not in D or k in HIDDEN: continue
            if k in SECRET_KEYS and v == "": continue
            try: S[k] = type(D[k])(v) if not isinstance(D[k], bool) else bool(v)
            except ValueError: pass
        S["sensitivity"] = max(1, min(100, S["sensitivity"]))
        S["delete_every"] = max(1, S["delete_every"])
        save(); audit("Settings changed")
        return jsonify(ok=True)
    return jsonify({k: ("" if k in SECRET_KEYS else S[k]) for k in D if k not in HIDDEN} | {"has_tg_token": bool(S["tg_token"])})

def pub(c): return {"brand": "tapo", "follow": False, "opts": {}, "url": "", "adj": {}} | {k: v for k, v in c.items() if k != "pass"} | {"has_pass": bool(c["pass"])}

@app.route("/api/cams", methods=["GET", "POST"])
def cams_api():
    if request.method == "POST":
        d = request.json
        n = max([int(c["id"][3:]) for c in S["cams"]] + [0]) + 1
        c = {"id": f"cam{n}", "name": clean_name(d.get("name") or f"Camera {n}"), "ip": d.get("ip", "").strip(), "user": d.get("user", ""),
             "pass": d.get("pass", ""), "stream": d.get("stream", "stream1"), "brand": d.get("brand", "tapo"),
             "url": d.get("url", "").strip(), "track": False, "night": "auto", "follow": False, "opts": {}}
        err = validate_cam(c)
        if err: return jsonify(error=err), 400
        S["cams"].append(c); save(); start_cam(c["id"]); audit(f"Camera added: {c['name']}")
    return jsonify([pub(c) for c in S["cams"]])

@app.route("/api/cams/probe", methods=["POST"])
def cam_probe():
    d = request.json
    base = {"ip": d.get("ip", "").strip(), "user": d.get("user", ""), "stream": "stream1", "url": "",
            "pass": d.get("pass") or (cfg(d.get("id")) or {}).get("pass", "")}
    if not base["ip"] or validate_cam({**base, "brand": "tapo"}): return jsonify(error="Enter the camera's IP address first."), 400
    found = {}
    def go(b):
        cap = cv2.VideoCapture(rtsp_url({**base, "brand": b}), cv2.CAP_FFMPEG)
        if cap.isOpened() and cap.read()[0]: found[b] = True
        cap.release()
    ts = [threading.Thread(target=go, args=(b,), daemon=True) for b in BRANDS if b != "custom"]
    for t in ts: t.start()
    end = time.time() + 15
    for t in ts: t.join(max(0, end - time.time()))
    hit = next((b for b in BRANDS if found.get(b)), None)
    if not hit: return jsonify(error="No video found. Check the address and login, or choose Other and paste the address."), 400
    audit(f"Auto-detected brand: {BRANDS[hit]}")
    return jsonify(brand=hit, label=BRANDS[hit])

@app.route("/api/cams/test", methods=["POST"])
def cam_test():
    d = request.json
    c = {"brand": d.get("brand", "tapo"), "ip": d.get("ip", "").strip(), "user": d.get("user", ""), "stream": d.get("stream", "stream1"),
         "pass": d.get("pass") or (cfg(d.get("id")) or {}).get("pass", ""), "url": d.get("url", "").strip()}
    err = validate_cam(c)
    if err or not (c["ip"] or c["url"]): return jsonify(error=err or "Enter the camera's address first."), 400
    res = {}
    def go():
        cap = cv2.VideoCapture(rtsp_url(c), cv2.CAP_FFMPEG)
        ok, f = cap.read() if cap.isOpened() else (False, None)
        res["size"] = f"{f.shape[1]}x{f.shape[0]}" if ok else ""; cap.release()
    t = threading.Thread(target=go, daemon=True); t.start(); t.join(12)
    if res.get("size"): return jsonify(ok=True, size=res["size"])
    return jsonify(error="Couldn't open the video. Check the brand, address and login."), 400

@app.route("/api/cams/<cid>", methods=["POST", "DELETE"])
def cam_edit(cid):
    c = cfg(cid)
    if c is None: return jsonify(error="Unknown camera"), 404
    if request.method == "DELETE":
        S["cams"].remove(c); audit(f"Camera removed: {c['name']}")
    else:
        d = request.json
        n = {**c, **{k: str(d[k]).strip() for k in ("name", "ip", "user", "stream", "brand", "url") if k in d}}
        n["name"] = clean_name(n["name"]) or c["name"]
        if d.get("pass"): n["pass"] = d["pass"]
        err = validate_cam(n)
        if err: return jsonify(error=err), 400
        c.update(n); audit(f"Camera edited: {c['name']}")
        if cid in cams: cams[cid]["reconnect"] = True
        tapos.pop(cid, None)
    save()
    return jsonify([pub(x) for x in S["cams"]])

@app.route("/api/cams/<cid>/<act>", methods=["POST"])
def cam_act(cid, act):
    c, d = cfg(cid), request.get_json(silent=True) or {}
    if c is None or cid not in cams: return jsonify(error="Unknown camera"), 404
    if act == "snapshot":
        f = cams[cid]["frame"]
        if f is None: return jsonify(error="Camera offline"), 400
        cv2.imwrite(os.path.join(SNAP, f"{cid}_manual_{datetime.now():%Y-%m-%d_%H-%M-%S}.jpg"), f)
        return jsonify(ok=True)
    if act == "adjust":
        try:
            rot = int(d.get("rot", 0))
            c["adj"] = {"bright": max(-60, min(60, int(d.get("bright", 0)))), "contrast": max(50, min(150, int(d.get("contrast", 100)))),
                        "sat": max(0, min(200, int(d.get("sat", 100)))), "rot": rot if rot in (0, 90, 180, 270) else 0, "mirror": bool(d.get("mirror"))}
        except (TypeError, ValueError): return jsonify(error="Bad value"), 400
        save(); return jsonify(ok=True)
    if act == "follow":
        c["follow"] = bool(d.get("on")); save(); return jsonify(ok=True)
    if act == "features" and c.get("brand", "tapo") != "tapo":
        c["features"] = {"model": BRANDS.get(c.get("brand"), "Camera"), "stream": True}; save(); return jsonify(c["features"])
    if c.get("brand", "tapo") != "tapo": return jsonify(error="This control is only for Tapo cameras."), 400
    audit(f"{act} on {c['name']}")
    try:
        if act == "siren": siren(cid, bool(d.get("on")))
        elif act == "night" and d.get("mode") in NIGHT:
            cam_call(cid, "setDayNightMode", NIGHT[d["mode"]]); c["night"] = d["mode"]; save()
        elif act == "track":
            cam_call(cid, "setAutoTrackTarget", bool(d.get("on"))); c["track"] = bool(d.get("on")); save()
        elif act in TAPO:
            cam_call(cid, TAPO[act], bool(d.get("on"))); c.setdefault("opts", {})[act] = bool(d.get("on")); save()
        elif act == "reboot": cam_call(cid, "reboot")
        elif act == "move": cam_call(cid, "moveMotor", max(-30, min(30, int(d.get("x", 0)))), max(-30, min(30, int(d.get("y", 0)))))
        elif act == "features": c["features"] = detect(cid); save(); return jsonify(c["features"])
        else: return jsonify(error="Unknown action"), 404
    except Exception:
        if act == "siren": cams[cid]["siren"] = False
        return jsonify(error="Couldn't reach the camera. Check its address and account. Some models, and newer Tapo firmware, don't allow this."), 400
    return jsonify(ok=True)

@app.route("/api/security")
def sec_info(): return jsonify(totp=bool(S["totp"]), audit=list(audit_log)[:30])

@app.route("/api/2fa/setup", methods=["POST"])
def tfa_setup():
    sec = base64.b32encode(os.urandom(10)).decode(); session["pending_totp"] = sec
    return jsonify(secret=sec)

@app.route("/api/2fa/enable", methods=["POST"])
def tfa_enable():
    sec = session.get("pending_totp")
    if not totp_ok(sec, request.json.get("code", "")): return jsonify(error="That code didn't match. Try again."), 400
    S["totp"] = sec; save(); session.pop("pending_totp", None); audit("Two-step sign-in turned on")
    return jsonify(ok=True)

@app.route("/api/2fa/disable", methods=["POST"])
def tfa_disable():
    d = request.json
    if not (check_password_hash(S["pw_hash"], d.get("password", "")) and totp_ok(S["totp"], d.get("code", ""))):
        return jsonify(error="Password or code is wrong."), 400
    S["totp"] = ""; save(); audit("Two-step sign-in turned off")
    return jsonify(ok=True)

@app.route("/api/signout_all", methods=["POST"])
def signout_all():
    audit("Signed out all devices")
    S["secret"] = secrets.token_hex(32); app.secret_key = S["secret"]; save(); session.clear()
    return jsonify(ok=True)

@app.route("/api/events")
def get_events(): return jsonify(events)

@app.route("/api/recordings")
def recordings():
    return jsonify([{"name": os.path.basename(f), "mb": round(os.path.getsize(f) / 1e6, 1),
                     "cam": os.path.basename(f).split("_")[0]} for f in reversed(files())])

@app.route("/rec/<name>")
def rec(name): return send_from_directory(REC, name, as_attachment=bool(request.args.get("dl")))

@app.route("/snap/<name>")
def snap(name): return send_from_directory(SNAP, name)

@app.route("/api/delete/<name>", methods=["POST"])
def delete(name):
    p = os.path.join(REC, os.path.basename(name))
    if os.path.exists(p): os.remove(p)
    return jsonify(ok=True)

LOGO = '<svg width="30" height="30" viewBox="0 0 24 24" aria-hidden="true"><defs><linearGradient id="lgA" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffd978"/><stop offset=".55" stop-color="#f2b84b"/><stop offset="1" stop-color="#d4922a"/></linearGradient></defs><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" fill="url(#lgA)" stroke="url(#lgA)" stroke-width="1.2" stroke-linejoin="round"/><circle cx="12" cy="11.6" r="4.7" fill="#0b1418"/><circle cx="12" cy="11.6" r="3.75" fill="none" stroke="#f2b84b" stroke-width=".5" opacity=".9"/><circle cx="12" cy="11.6" r="2.3" fill="#1b3a45"/><circle cx="12" cy="11.6" r="1.05" fill="#ff5a47"/><circle cx="11.2" cy="10.8" r=".45" fill="#fff" opacity=".85"/></svg>'

STYLE = """:root{--bg:#0b1418;--s1:#111f25;--s2:#172b33;--line:#22383f;--text:#e7ecea;--dim:#85999d;--amber:#f2b84b;--ok:#4fd1a1;--red:#ff5a47;color-scheme:dark}
@media(prefers-color-scheme:light){:root:not([data-theme=dark]){--bg:#f3f0e8;--s1:#ffffff;--s2:#ebe6da;--line:#d8d1c0;--text:#15262b;--dim:#5f7377;--amber:#b87800;--ok:#13795a;--red:#d63d2c;color-scheme:light}}
:root[data-theme=light]{--bg:#f3f0e8;--s1:#ffffff;--s2:#ebe6da;--line:#d8d1c0;--text:#15262b;--dim:#5f7377;--amber:#b87800;--ok:#13795a;--red:#d63d2c;color-scheme:light}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 0 0,color-mix(in srgb,var(--amber) 12%,transparent),transparent 50%) fixed,var(--bg);color:var(--text);font:15px/1.55 "Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
h1,h2,h3{margin:0;letter-spacing:-.02em}button,input,select{font:inherit}
button{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:var(--amber);color:#1a1405;border:0;border-radius:10px;padding:10px 16px;font-weight:600;cursor:pointer}
button.ghost{background:var(--s2);color:var(--text);border:1px solid var(--line)}
button.danger{background:rgba(255,90,71,.14);color:var(--red);border:1px solid rgba(255,90,71,.35)}
button.danger.hot{background:var(--red);color:#fff}
input,select{background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:9px 12px}
:focus-visible{outline:2px solid var(--amber);outline-offset:2px}
@media(pointer:coarse){button,input,select{min-height:44px}}"""

AUTH = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Tapo Watch</title><link rel=icon href=/static/favicon.png>
<script>try{document.documentElement.dataset.theme=localStorage.getItem("theme")||""}catch(e){}</script>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel=stylesheet>
<style>""" + STYLE + """
body{display:grid;place-items:center;min-height:100vh}form{width:min(380px,92vw);display:grid;gap:14px;background:var(--s1);padding:30px;border-radius:18px;border:1px solid var(--line)}
.lg{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px}p{margin:0;color:var(--red)}h1{font-size:22px}</style>
<form method=post><div class=lg>""" + LOGO + """Tapo Watch</div><h1>{{title}}</h1>{% if setup %}<span style="color:var(--dim)">This password protects your camera. You'll need it each time you open the site.</span>{% endif %}
<input type=password name=pw placeholder=Password autofocus required>{% if setup %}<input type=password name=pw2 placeholder="Repeat password" required>{% endif %}
{% if totp %}<input name=code placeholder="6-digit code" inputmode=numeric autocomplete=one-time-code required>{% endif %}{% if err %}<p>{{err}}</p>{% endif %}<button>{{'Save password' if setup else 'Sign in'}}</button></form>"""

PAGE = """<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Tapo Watch</title><link rel=icon href=/static/favicon.png>
<script>try{document.documentElement.dataset.theme=localStorage.getItem("theme")||""}catch(e){}</script><link rel=manifest href=/manifest.json><meta name=theme-color content="#0b1418"><meta name=apple-mobile-web-app-capable content=yes><link rel=apple-touch-icon href=/icon192.png>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel=stylesheet>
<style>""" + STYLE + """
.app{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
nav{background:var(--s1);border-right:1px solid var(--line);padding:20px 12px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px;margin:0 8px 22px}
nav a{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:10px;color:var(--dim);cursor:pointer;text-decoration:none;font-weight:500}
nav a.on{background:var(--s2);color:var(--amber)}nav .sp{flex:1}
main{padding:24px;max-width:980px;width:100%}.tab{display:none}.tab.on{display:block}
h2{font-size:22px;margin-bottom:16px}
.view{position:relative;background:#000;border-radius:16px;overflow:hidden;aspect-ratio:16/9;border:1px solid var(--line)}
.view img,.view video{width:100%;height:100%;object-fit:contain;display:block}
.off{position:absolute;inset:0;display:grid;place-items:center;color:var(--dim);text-align:center;padding:20px}
.tag{position:absolute;top:12px;left:12px;display:flex;align-items:center;gap:6px;background:rgba(11,20,24,.72);padding:4px 12px;border-radius:99px;font-size:13px;font-weight:600}
.tag i{width:8px;height:8px;border-radius:50%;background:var(--dim)}.tag.rec i{background:var(--red)}.tag.on i{background:var(--ok)}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.chip{padding:4px 12px;border-radius:99px;background:var(--s1);border:1px solid var(--line);color:var(--dim);font-size:13px;font-weight:500}
.chip.on{border-color:transparent;color:#0b1418;font-weight:600}.chip.g.on{background:var(--ok)}.chip.a.on{background:var(--amber)}
.bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:4px}
.seg{display:inline-flex;background:var(--s1);border:1px solid var(--line);border-radius:12px;padding:3px}
.seg button{background:none;color:var(--dim);padding:7px 14px;border-radius:9px}.seg button.on{background:var(--s2);color:var(--amber)}
.lbl{color:var(--dim);font-size:13px;margin:16px 0 6px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
.card{background:var(--s1);border:1px solid var(--line);border-radius:14px;overflow:hidden}.card img{width:100%;aspect-ratio:16/9;object-fit:cover;display:block;cursor:pointer}
.card div{padding:9px 14px;display:flex;justify-content:space-between;color:var(--dim);font-size:13px}
.row{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:12px 0;border-top:1px solid var(--line)}
.row a{cursor:pointer;color:var(--text)}.row .ac{display:flex;gap:8px;align-items:center}.row .ac a{color:var(--dim);display:flex}
.grp{background:var(--s1);border:1px solid var(--line);border-radius:16px;padding:8px 20px 14px;margin-bottom:16px}
.grp h3{font-size:16px;margin:14px 0 4px}.f{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:11px 0;border-top:1px solid var(--line)}
.f small{display:block;color:var(--dim);font-size:12px}.f input[type=text],.f input[type=password],.f input[type=number],.f input[type=time],.f select{width:190px;max-width:48vw}
.sw{position:relative;display:inline-block}.sw input{position:absolute;opacity:0;width:100%;height:100%;margin:0;cursor:pointer}
.sw i{display:block;width:44px;height:26px;border-radius:99px;background:var(--line);position:relative;transition:background .15s}
.sw i:after{content:"";position:absolute;top:3px;left:3px;width:20px;height:20px;border-radius:50%;background:#fff;transition:left .15s}
.sw input:checked+i{background:var(--ok)}.sw input:checked+i:after{left:21px}.sw input:focus-visible+i{outline:2px solid var(--amber)}
.siren{width:150px;height:150px;border-radius:50%;flex-direction:column;font-size:15px;margin:10px auto 22px;display:flex}
.muted{color:var(--dim)}#toast{position:fixed;left:50%;transform:translateX(-50%);bottom:84px;background:var(--s2);border:1px solid var(--line);padding:10px 18px;border-radius:12px;display:none;z-index:9;max-width:90vw}
.adj{background:var(--s1);border:1px solid var(--line);border-radius:14px;padding:6px 18px;margin-top:14px}.adj summary{cursor:pointer;padding:8px 0;font-weight:600}
input[type=range]{width:200px;max-width:48vw;accent-color:var(--amber);padding:0}.pad{display:grid;grid-template-columns:repeat(3,64px);gap:6px;justify-content:start}
.ph{position:absolute;inset:0;margin:auto;width:84px;height:84px;color:var(--dim);opacity:.6}.view img{position:relative}.empty svg{width:110px;height:110px;color:var(--amber);opacity:.85}
@media(max-width:760px){.app{grid-template-columns:1fr}nav{position:fixed;bottom:0;left:0;right:0;top:auto;height:auto;flex-direction:row;justify-content:space-around;z-index:5;border-top:1px solid var(--line);border-right:0;padding:6px 6px calc(6px + env(safe-area-inset-bottom,0px))}
nav a{flex-direction:column;gap:2px;font-size:11px;padding:6px 8px}.brand,nav .sp,nav .lo{display:none}main{padding:14px 14px 96px}}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
.tiles{display:grid;gap:12px;grid-template-columns:1fr}.tiles.multi{grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr))}
.tile{cursor:pointer}.tiles.multi .tile.sel{outline:2px solid var(--amber)}
.empty{background:var(--s1);border:1px dashed var(--line);border-radius:16px;padding:40px 20px;text-align:center;color:var(--dim);line-height:2.4}
button.ghost.hot{background:var(--ok);color:#0b1418;border-color:transparent}
.f a{color:var(--amber);font-weight:600;text-decoration:none;white-space:nowrap}.f code{background:var(--bg);padding:1px 6px;border-radius:6px}
.row small{display:block;color:var(--dim);font-size:12px}

</style><div class=app><nav><div class=brand>""" + LOGO + """Tapo Watch</div>
<a data-t=live class=on><i data-i=video></i><span>Live</span></a><a data-t=events><i data-i=bell></i><span>Events</span></a><a data-t=alarm><i data-i=siren></i><span>Alarm</span></a>
<a data-t=recs><i data-i=folder></i><span>Clips</span></a><a data-t=set><i data-i=sliders></i><span>Settings</span></a><span class=sp></span><a class=lo onclick=thm()><i data-i=sun></i><span>Theme</span></a><a class=lo href=/logout><i data-i=out></i><span>Sign out</span></a></nav>
<main>
<div class="tab on" id=live><div id=tiles class=tiles></div>
<div id=ctl style="display:none">
<div class=chips><span class="chip cn"></span><span id=mo class="chip a">Motion</span><span id=fa class="chip g">Face</span><span id=arm class="chip g">Armed</span></div>
<div class="lbl tonly">Night vision</div>
<div class="bar tonly"><div class=seg id=nm><button data-m=auto><i data-i=auto data-s=18></i>Auto</button><button data-m=day><i data-i=sun data-s=18></i>Day</button><button data-m=night><i data-i=moon data-s=18></i>Night</button></div></div>
<div class=lbl>Actions</div>
<div class=bar><button class="ghost tonly" id=trk onclick=track() title="Moves the camera (Tapo models with a motor)"><i data-i=target></i>Auto-track</button><button class=ghost id=fol onclick=follow() title="Zooms in on movement. Works on any camera."><i data-i=target></i>Smart follow</button><button class=ghost id=ovl onclick=ovl()><i data-i=eye></i>Overlays</button>
<button class=ghost onclick=snap()><i data-i=cam></i>Snapshot</button><button class=ghost onclick=full()><i data-i=full></i>Full screen</button>
<button class="danger tonly" id=sir1 onclick=siren()><i data-i=siren></i><span>Siren</span></button></div>
<details class=adj><summary>Adjust picture</summary>
<div class=f><span>Brightness</span><input type=range id=ad_bright min=-60 max=60 value=0 oninput=adj()></div>
<div class=f><span>Contrast</span><input type=range id=ad_contrast min=50 max=150 value=100 oninput=adj()></div>
<div class=f><span>Color</span><input type=range id=ad_sat min=0 max=200 value=100 oninput=adj()></div>
<div class=f><span>Rotate</span><select id=ad_rot onchange=adj()><option value=0>None</option><option value=90>90 degrees</option><option value=180>180 degrees</option><option value=270>270 degrees</option></select></div>
<div class=f><span>Mirror</span><label class=sw><input type=checkbox id=ad_mirror onchange=adj()><i></i></label></div>
<div class=f><span></span><button class=ghost onclick=adjr()>Reset</button></div></details>
<div class="lbl tonly mv">Move camera</div><div class="pad tonly mv"><span></span><button class=ghost aria-label=Up onclick="mv(0,10)">&uarr;</button><span></span><button class=ghost aria-label=Left onclick="mv(-10,0)">&larr;</button><span></span><button class=ghost aria-label=Right onclick="mv(10,0)">&rarr;</button><span></span><button class=ghost aria-label=Down onclick="mv(0,-10)">&darr;</button><span></span></div>
<div class="lbl tonly">Tapo controls</div><div class="bar tonly" id=tx></div></div>
<p class="muted nd"></p></div>
<div class=tab id=events><h2>Events</h2><div class=grid id=evl></div></div>
<div class=tab id=alarm><h2>Alarm</h2><p class=muted style="text-align:center">Siren controls apply to <b class=cn></b>.</p>
<button class="danger siren" id=sir2 onclick=siren()><i data-i=siren data-s=44></i><span>Sound siren</span></button><div id=aform></div></div>
<div class=tab id=recs><h2>Clips</h2><p class="muted nd"></p><div class=view id=pl style="display:none;margin-bottom:12px"><video id=vid controls></video></div><div id=rl></div></div>
<div class=tab id=set><h2>Settings</h2>
<div class=grp><h3>Cameras</h3><div id=camlist></div><div class=lbl id=cfh>Add camera</div>
<div class=f><span>Name</span><input type=text id=cf_name placeholder="Front door"></div>
<div class=f><span>Brand<small id=cf_hint></small></span><select id=cf_brand onchange=bh()><option value=tapo>Tapo</option><option value=cpplus>CP Plus / Dahua</option><option value=cpplus2>CP Plus (older, port 5543)</option><option value=hikvision>Hikvision</option><option value=reolink>Reolink</option><option value=custom>Other (RTSP address)</option></select></div>
<div class=f id=cf_urlrow style="display:none"><span>Video address<small>Use {user} and {pass} in place of the login</small></span><input type=text id=cf_url placeholder="rtsp://{user}:{pass}@192.168.1.20:554/stream"></div>
<div class=f id=cf_iprow><span>IP address<small>Find it in the camera's app or your router</small></span><input type=text id=cf_ip></div>
<div class=f><span>Camera user</span><input type=text id=cf_user></div>
<div class=f><span>Camera password</span><input type=password id=cf_pass></div>
<div class=f><span>Quality</span><select id=cf_stream><option value=stream1>High</option><option value=stream2>Low (smoother)</option></select></div>
<div class=f><button onclick=cs()>Save camera</button><button class=ghost onclick=ct()>Test connection</button><button class=ghost onclick=cp()>Find brand</button><button class=ghost onclick="ce(null)">Clear</button></div></div>
<div id=form></div>
<div class=grp><h3>Where footage is saved</h3>
<div class=f><span>This computer<small>Always on. Clips go in the recordings folder.</small></span></div>
<div class=f><span>Camera SD card<small>The camera records to it by itself, even when this app is off. Turn it on in the Tapo app under the camera's storage settings (wording varies by model).</small></span></div>
<div class=f><span>Cloud backup<small>Install rclone, run <code>rclone config</code> to create a remote, then type its name in Cloud backup above.</small></span><a href="https://rclone.org/downloads/" target=_blank rel=noopener>Get rclone</a></div>
<div class=lbl>Free cloud storage that works with rclone</div>
<div class=f><span>MEGA<small>20 GB, encrypted</small></span><a href="https://mega.io" target=_blank rel=noopener>Sign up</a></div>
<div class=f><span>Google Drive<small>15 GB, shared with Gmail</small></span><a href="https://drive.google.com" target=_blank rel=noopener>Sign up</a></div>
<div class=f><span>pCloud<small>Up to 10 GB</small></span><a href="https://www.pcloud.com" target=_blank rel=noopener>Sign up</a></div>
<div class=f><span>Koofr<small>10 GB</small></span><a href="https://koofr.eu" target=_blank rel=noopener>Sign up</a></div>
<div class=f><span>Filen<small>10 GB, encrypted</small></span><a href="https://filen.io" target=_blank rel=noopener>Sign up</a></div>
<div class=f><span>Icedrive<small>10 GB</small></span><a href="https://icedrive.net" target=_blank rel=noopener>Sign up</a></div>
<div class=f><span>Proton Drive<small>5 GB, encrypted</small></span><a href="https://proton.me/drive" target=_blank rel=noopener>Sign up</a></div>
<div class=f><span>OneDrive<small>5 GB</small></span><a href="https://onedrive.live.com" target=_blank rel=noopener>Sign up</a></div></div>
<div class=grp><h3>Appearance</h3><div class=f><span>Theme<small>Auto follows your phone or computer</small></span><select id=thsel onchange=thm(this.value)><option value="">Auto</option><option value=light>Light</option><option value=dark>Dark</option></select></div></div>
<div class=grp><h3>Security</h3>
<div class=f><span>Two-step sign-in<small id=tfs>Checking...</small></span><button class=ghost id=tfb onclick=tf()>Set up</button></div>
<div id=tfbox style="display:none"><div class=f><span>Add this key to an authenticator app (Google Authenticator, Authy, 1Password)<small id=tfk style="word-break:break-all"></small></span></div>
<div class=f><input type=text id=tfc placeholder="6-digit code" inputmode=numeric><button onclick=tfe()>Turn on</button></div></div>
<div class=f><span>Sign out everywhere<small>Ends every signed-in phone and computer</small></span><button class=danger onclick=sao()>Sign out all</button></div>
<div class=lbl>Recent security activity</div><div id=aud class=muted style="font-size:12px;line-height:1.8"></div></div>
<div class=grp><h3>Change password</h3><div class=f><span>Current</span><input type=password id=pc></div><div class=f><span>New (8+ characters)</span><input type=password id=pn></div>
<div class=f><span></span><button class=ghost onclick=pw()>Update password</button></div></div></div>
</main></div><div id=toast></div>
<script>
const $=i=>document.getElementById(i);let cfg={},cl=[],sel=null,editing=null;window._s={};
const P={target:'<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',eye:'<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/>',video:'<path d="m16 13 5.223 3.482a.5.5 0 0 0 .777-.416V7.87a.5.5 0 0 0-.752-.432L16 10.5"/><rect x="2" y="6" width="14" height="12" rx="2"/>',
bell:'<path d="M10.268 21a2 2 0 0 0 3.464 0"/><path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326"/>',
folder:'<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
sliders:'<path d="M21 4h-7M10 4H3M21 12h-9M8 12H3M21 20h-5M12 20H3M14 2v4M8 10v4M16 18v4"/>',
siren:'<path d="M7 18v-6a5 5 0 1 1 10 0v6"/><path d="M5 21a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-1a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2z"/><path d="M21 12h1M18.5 4.5 18 5M2 12h1M12 2v1M4.929 4.929l.707.707M12 12v6"/>',
moon:'<path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401"/>',
sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>',
auto:'<circle cx="12" cy="12" r="10"/><path d="M12 18a6 6 0 0 0 0-12v12z"/>',
cam:'<path d="M13.997 4a2 2 0 0 1 1.76 1.05l.486.9A2 2 0 0 0 18.003 7H20a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h1.997a2 2 0 0 0 1.759-1.048l.489-.904A2 2 0 0 1 10.004 4z"/><circle cx="12" cy="13" r="3"/>',
out:'<path d="m16 17 5-5-5-5M21 12H9M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>',
trash:'<path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
dl:'<path d="M12 15V3M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5"/>',
full:'<path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3"/>'};
const ic=(n,s=20)=>`<svg width=${s} height=${s} viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=1.8 stroke-linecap=round stroke-linejoin=round aria-hidden=true>${P[n]}</svg>`;
const hy=()=>document.querySelectorAll('i[data-i]').forEach(e=>{e.outerHTML=ic(e.dataset.i,+e.dataset.s||20)});
const J=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
function toast(m){const t=$('toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',3000)}

const G=[["Detection",[["sensitivity","Motion sensitivity","number","1 to 100"],["detect_faces","Detect faces","bool"],["show_boxes","Show detection boxes on video","bool"],["enhance","Brighten dark video","bool","Clearer picture in low light"],["record","Record clips","bool"],["post_roll","Keep recording after motion (seconds)","number"],["cooldown","Seconds between events","number"]]],
["Arm schedule",[["schedule_on","Only detect during set hours","bool"],["arm_from","From","time"],["arm_to","Until","time"]]],
["Clean-up schedule",[["auto_delete","Delete old clips automatically","bool"],["delete_time","Delete at","time"],["delete_every","Repeat every (days)","number","The next run shows on the Clips tab"],["keep_days","Keep clips for (days, 0 = all)","number"],["max_gb","Storage limit (GB)","number","Oldest clips go first"]]],
["Cloud backup",[["cloud_on","Upload clips to the cloud","bool"],["cloud_remote","rclone remote name","text","For example: mega"],["cloud_path","Folder in the cloud","text"],["cloud_delete_local","Remove from this computer after upload","bool"]]],
["Protection",[["lan_only","Only allow home Wi-Fi and VPN","bool","Blocks sign-in attempts from the open internet"],["offline_alert","Alert if a camera goes offline","bool","Sends a Telegram message after 1 minute"],["restore_outage","Re-apply camera settings after an outage","bool","Night vision, privacy, tracking and the other toggles"]]],
["Phone alerts",[["tg_token","Telegram bot token","password","Create one with @BotFather"],["tg_chat","Telegram chat ID","text"]]]];
const GA=[["Automatic siren",[["alarm_on_event","Sound siren on detection","bool","Uses your camera's built-in siren"],["alarm_trigger","Trigger on","select",["face","any"],["Faces only","Faces and motion"]],["alarm_secs","Siren length (seconds)","number"]]]];
function rf(arr,el){$(el).innerHTML=arr.map(([t,fs])=>`<div class=grp><h3>${t}</h3>`+fs.map(([k,l,ty,h,nm])=>{
const c=ty=='bool'?`<label class=sw><input type=checkbox id=s_${k} ${cfg[k]?'checked':''}><i></i></label>`:ty=='select'?`<select id=s_${k}>${h.map((o,i)=>`<option value=${o} ${cfg[k]==o?'selected':''}>${nm[i]}</option>`).join('')}</select>`:
`<input type=${ty} id=s_${k} value="${ty=='password'?'':cfg[k]}" ${ty=='password'&&cfg['has_'+k]?'placeholder="Saved. Type to replace"':''}>`;
return `<div class=f><span>${l}${ty!='select'&&h?`<small>${h}</small>`:''}</span>${c}</div>`}).join('')+`</div>`).join('')+`<button onclick=sv()>Save settings</button><br><br>`}
async function sv(){const o={};[...G,...GA].forEach(([t,fs])=>fs.forEach(([k,l,ty])=>{const e=$('s_'+k);if(e)o[k]=ty=='bool'?e.checked:ty=='number'?+e.value:e.value}));
await J('/api/settings',o);toast('Settings saved');cfg=await (await fetch('/api/settings')).json()}
async function pw(){const r=await J('/api/password',{current:$('pc').value,new:$('pn').value});const d=await r.json();toast(d.error||'Password updated');if(r.ok){$('pc').value=$('pn').value=''}}
const cur=()=>cl.find(c=>c.id==sel),cname=i=>(cl.find(c=>c.id==i)||{name:i}).name;
function tiles(){const t=$('tiles');if(!cl.length){t.className='tiles';t.innerHTML='<div class=empty><svg viewBox="0 0 64 64" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round aria-hidden=true><rect x=8 y=18 width=34 height=24 rx=5 /><path d="M42 27l14-7v24l-14-7M14 52h22M20 8c5 3 8 3 12 0M24 4c3 2 5 2 8 0"/></svg><br>No cameras yet.<br><button onclick="gos()">Add a camera</button></div>';$('ctl').style.display='none';return}
$('ctl').style.display='block';t.className='tiles'+(cl.length>1?' multi':'');
t.innerHTML=cl.map(c=>`<div class="view tile${c.id==sel?' sel':''}" data-c=${c.id} onclick="pick('${c.id}')"><svg class=ph viewBox="0 0 64 64" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round aria-hidden=true><rect x=8 y=18 width=34 height=24 rx=5 /><path d="M42 27l14-7v24l-14-7M14 52h22"/></svg><img src=/live/${c.id} alt="${c.name}"><span class=tag id=tag_${c.id}><i></i><span>${c.name}</span></span></div>`).join('')}
function pick(id){sel=id;document.querySelectorAll('.tile').forEach(e=>e.classList.toggle('sel',e.dataset.c==id));const c=cur();document.querySelectorAll('.cn').forEach(e=>e.textContent=c.name);nm();$('trk').classList.toggle('hot',!!c.track);$('fol').classList.toggle('hot',!!c.follow);document.querySelectorAll('.tonly').forEach(e=>e.style.display=c.brand=='tapo'?'':'none');txr();adl();fx()}
function nm(){const c=cur();document.querySelectorAll('#nm button').forEach(b=>b.classList.toggle('on',!!c&&b.dataset.m==c.night))}
function camlist(){$('camlist').innerHTML=cl.length?cl.map(c=>`<div class=row><span>${c.name}<small>${c.ip||'No address yet'}</small></span><span class=ac><a onclick="fd('${c.id}')" style="cursor:pointer">Detect features</a><a onclick="ce('${c.id}')" style="cursor:pointer">Edit</a><a onclick="cx('${c.id}')" style="cursor:pointer;color:var(--red)">Remove</a></span></div>`).join(''):'<p class=muted>No cameras yet.</p>'}
function ce(id){const c=cl.find(x=>x.id==id)||{};editing=id;['name','ip','user','url'].forEach(k=>$('cf_'+k).value=c[k]||'');$('cf_brand').value=c.brand||'tapo';bh();$('cf_pass').value='';$('cf_pass').placeholder=c.has_pass?'Saved. Type to replace':'';$('cf_stream').value=c.stream||'stream1';$('cfh').textContent=id?'Edit camera':'Add camera'}
function after(){if(!cl.find(c=>c.id==sel))sel=cl[0]?cl[0].id:null;tiles();camlist();if(sel)pick(sel)}
async function cs(){const b={name:$('cf_name').value,ip:$('cf_ip').value,user:$('cf_user').value,pass:$('cf_pass').value,stream:$('cf_stream').value,brand:$('cf_brand').value,url:$('cf_url').value};
const r=await J(editing?'/api/cams/'+editing:'/api/cams',b);const d=await r.json();if(r.ok){cl=d;after();ce(null);toast('Camera saved')}else toast(d.error)}
async function cx(id){if(confirm('Remove '+cname(id)+'?')){cl=await (await fetch('/api/cams/'+id,{method:'DELETE'})).json();after()}}
async function act(a,b){const r=await J(`/api/cams/${sel}/${a}`,b);const d=await r.json();if(!r.ok)toast(d.error);return r.ok}
document.querySelectorAll('#nm button').forEach(b=>b.onclick=async()=>{if(await act('night',{mode:b.dataset.m})){cur().night=b.dataset.m;nm()}});
async function track(){const on=!cur().track;if(await act('track',{on})){cur().track=on;pick(sel);toast(on?'Auto-tracking on':'Auto-tracking off')}}
async function siren(){const x=window._s[sel]||{};await act('siren',{on:!x.siren})}
async function snap(){if(await act('snapshot'))toast('Snapshot saved')}
function full(){const t=document.querySelector('.tile.sel')||document.querySelector('.tile');if(t&&t.requestFullscreen)t.requestFullscreen()}
async function ovl(){cfg.show_boxes=!cfg.show_boxes;await J('/api/settings',{show_boxes:cfg.show_boxes});$('ovl').classList.toggle('hot',cfg.show_boxes);toast(cfg.show_boxes?'Overlays on':'Overlays off')}
document.querySelectorAll('nav a[data-t]').forEach(a=>a.onclick=()=>{document.querySelectorAll('.tab,nav a').forEach(e=>e.classList.remove('on'));a.classList.add('on');$(a.dataset.t).classList.add('on');if(a.dataset.t=='events')ev();if(a.dataset.t=='recs')rl();if(a.dataset.t=='set')sec()});
async function st(){try{const s=await (await fetch('/api/status')).json();window._s=s.cams;
cl.forEach(c=>{const x=s.cams[c.id]||{},t=$('tag_'+c.id);if(t){t.className='tag '+(x.recording?'rec':x.online?'on':'');t.lastChild.textContent=c.name+(x.recording?' (Recording)':x.online?'':' (Offline)')}});
const x=s.cams[sel]||{};$('mo').classList.toggle('on',!!x.motion);$('fa').classList.toggle('on',x.faces>0);$('fa').textContent='Face'+(x.faces?' ('+x.faces+')':'');
$('arm').classList.toggle('on',!!x.armed);$('arm').textContent=x.armed===false?'Off schedule':'Armed';
['sir1','sir2'].forEach(i=>{$(i).classList.toggle('hot',!!x.siren);$(i).lastChild.textContent=x.siren?'Stop siren':(i=='sir1'?'Siren':'Sound siren')});
const nd=s.clips+' clips using '+s.used_mb+' MB.'+(s.next_delete?' Next clean-up: '+s.next_delete+'.':'')+(s.cloud?' Cloud backup is on.':s.cloud_wanted?' Cloud backup needs rclone installed.':'');
document.querySelectorAll('.nd').forEach(e=>e.textContent=nd)}catch(e){}}
async function ev(){const r=await (await fetch('/api/events')).json();$('evl').innerHTML=r.length?r.map(e=>`<div class=card><img src="/snap/${e.snap}" loading=lazy alt="${e.kind}" onclick="window.open(this.src)"><div><span>${cname(e.cam)}: ${e.kind=='face'?'Face':'Motion'}</span><span>${e.t.slice(5).replace('T',' ')}</span></div></div>`).join(''):'<p class=muted>No events yet. Motion and faces show up here with a snapshot.</p>'}
async function rl(){const r=await (await fetch('/api/recordings')).json();$('rl').innerHTML=r.length?r.map(f=>`<div class=row><a onclick="pl('${f.name}')">${cname(f.cam)}<small>${f.name.replace(/^cam[0-9]+_/,'').replace('.mp4','').replace('_',' ')}</small></a><span class=ac><span class=muted>${f.mb} MB</span><a href="/rec/${f.name}?dl=1" aria-label=Download>${ic('dl',18)}</a><a onclick="dl('${f.name}')" aria-label=Delete style="cursor:pointer;color:var(--red)">${ic('trash',18)}</a></span></div>`).join(''):'<p class=muted>No clips yet. They appear when motion or a face is detected.</p>'}
function pl(n){$('pl').style.display='block';$('vid').src='/rec/'+n;$('vid').play()}
async function dl(n){if(confirm('Delete '+n+'?')){await J('/api/delete/'+n);rl()}}
const BR={tapo:'Tapo app: Advanced settings, Camera account',cpplus:'Use the camera login. Port 554.',cpplus2:'For CP Plus models that use port 5543',hikvision:'Use the camera login. Port 554.',reolink:'Use the camera login. Port 554.',custom:'Paste the full video address'};
function bh(){const b=$('cf_brand').value;$('cf_hint').textContent=BR[b];$('cf_urlrow').style.display=b=='custom'?'':'none';$('cf_iprow').style.display=b=='custom'?'none':''}
async function ct(){toast('Testing the connection...');const r=await J('/api/cams/test',{id:editing,brand:$('cf_brand').value,ip:$('cf_ip').value,user:$('cf_user').value,pass:$('cf_pass').value,stream:$('cf_stream').value,url:$('cf_url').value});const d=await r.json();toast(r.ok?'Connected. Video is '+d.size:d.error)}
const TX=[['privacy','Privacy mode'],['led','Status light'],['person','Person detection'],['tamper','Tamper alert'],['flip','Flip image']];
function txr(){const c=cur();if(!c)return;const o=c.opts||{},f=c.features||{};$('tx').innerHTML=TX.filter(([k])=>f[k]!==false).map(([k,l])=>`<button class="ghost${o[k]?' hot':''}" onclick="tx('${k}')">${l}</button>`).join('')+'<button class=ghost onclick="tx(&quot;reboot&quot;)">Restart camera</button>'}
async function tx(k){const c=cur();if(k=='reboot'){if(confirm('Restart '+c.name+'?')&&await act('reboot'))toast('Restarting');return}
c.opts=c.opts||{};const on=!c.opts[k];if(await act(k,{on})){c.opts[k]=on;txr()}}
async function follow(){const c=cur(),on=!c.follow;if(await act('follow',{on})){c.follow=on;pick(sel);toast(on?'Smart follow on':'Smart follow off')}}
async function sec(){const d=await (await fetch('/api/security')).json();window._t=d.totp;$('tfs').textContent=d.totp?'On. You enter a code each time you sign in.':'Off. Adds a 6-digit code from your phone at sign-in.';$('tfb').textContent=d.totp?'Turn off':'Set up';
$('aud').innerHTML=d.audit.map(l=>'<div>'+l.replace(/</g,'&lt;')+'</div>').join('')||'Nothing yet.'}
async function tf(){if(window._t){const password=prompt('Your password'),code=prompt('6-digit code');if(!password||!code)return;const r=await J('/api/2fa/disable',{password,code});const d=await r.json();toast(d.error||'Two-step sign-in is off');sec();return}
const d=await (await J('/api/2fa/setup')).json();$('tfk').textContent=d.secret;$('tfbox').style.display='block'}
async function tfe(){const r=await J('/api/2fa/enable',{code:$('tfc').value});const d=await r.json();toast(d.error||'Two-step sign-in is on');if(r.ok){$('tfbox').style.display='none';$('tfc').value=''}sec()}
async function sao(){if(confirm('Sign out every device, including this one?')){await J('/api/signout_all');location.href='/login'}}
let adt;function adj(){clearTimeout(adt);adt=setTimeout(()=>{const c=cur();c.adj={bright:+$('ad_bright').value,contrast:+$('ad_contrast').value,sat:+$('ad_sat').value,rot:+$('ad_rot').value,mirror:$('ad_mirror').checked};act('adjust',c.adj)},300)}
function adl(){const a=cur().adj||{};$('ad_bright').value=a.bright||0;$('ad_contrast').value=a.contrast||100;$('ad_sat').value=a.sat==null?100:a.sat;$('ad_rot').value=a.rot||0;$('ad_mirror').checked=!!a.mirror}
function adjr(){cur().adj={};adl();act('adjust',{bright:0,contrast:100,sat:100,rot:0,mirror:false})}
function fx(){const c=cur();if(c.brand=='tapo'&&(c.features||{}).motor===false)document.querySelectorAll('.mv,#trk').forEach(e=>e.style.display='none')}
async function mv(x,y){await act('move',{x,y})}
async function fd(id){sel=id;pick(id);toast('Checking what this camera can do...');const r=await J('/api/cams/'+id+'/features');const d=await r.json();if(!r.ok){toast(d.error);return}
cur().features=d;pick(id);const on=Object.keys(d).filter(k=>d[k]===true).join(', ');toast((d.model||'Camera')+': '+(on||'basic video only'))}
async function cp(){if(!confirm('This tries up to 5 video addresses on the camera. Make sure the login is right first, because a few wrong logins can lock some cameras for a while. Continue?'))return;toast('Looking for the camera...');
const r=await J('/api/cams/probe',{id:editing,ip:$('cf_ip').value,user:$('cf_user').value,pass:$('cf_pass').value});const d=await r.json();if(r.ok){$('cf_brand').value=d.brand;bh();toast('Found: '+d.label)}else toast(d.error)}
function thm(v){const o=['','light','dark'];let t=localStorage.getItem('theme')||'';if(v===undefined)v=o[(o.indexOf(t)+1)%3];localStorage.setItem('theme',v);document.documentElement.dataset.theme=v;if($('thsel'))$('thsel').value=v;toast('Theme: '+(v||'auto'))}
function gos(){document.querySelector("nav a[data-t=set]").click()}
(async()=>{cfg=await (await fetch('/api/settings')).json();cl=await (await fetch('/api/cams')).json();rf(G,'form');rf(GA,'aform');after();ce(null);hy();$('thsel').value=localStorage.getItem('theme')||'';$('ovl').classList.toggle('hot',cfg.show_boxes);st();setInterval(st,1500)})();
</script>"""

@app.route("/manifest.json")
def manifest():
    return jsonify(name="Tapo Watch", short_name="Tapo Watch", start_url="/", display="standalone",
                   background_color="#0e1a1f", theme_color="#0e1a1f",
                   icons=[{"src": f"/icon{n}.png", "sizes": f"{n}x{n}", "type": "image/png", "purpose": "any maskable"} for n in (192, 512)])

@app.route("/icon<int:n>.png")
def icon(n):
    import numpy as np
    n = 192 if n <= 192 else 512
    p = os.path.join(BASE, "static", f"icon-{n}.png")
    if os.path.exists(p): return send_from_directory(os.path.join(BASE, "static"), f"icon-{n}.png")
    img = np.full((n, n, 3), (31, 26, 14), np.uint8)
    c = (n // 2, n // 2)
    cv2.circle(img, c, n // 3, (75, 184, 242), n // 14, cv2.LINE_AA)
    cv2.circle(img, c, n // 8, (71, 90, 255), -1, cv2.LINE_AA)
    return Response(cv2.imencode(".png", img)[1].tobytes(), mimetype="image/png")

@app.route("/")
def index(): return render_template_string(PAGE)

if __name__ == "__main__":
    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp"
    migrate()
    for f in glob.glob(os.path.join(REC, "*.mp4")):  # half-written clips from a power cut
        if os.path.getsize(f) < 1024: os.remove(f)
    for c in S["cams"]: start_cam(c["id"])
    threading.Thread(target=cleanup_loop, daemon=True).start()
    import socket
    try:
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); t.connect(("8.8.8.8", 80))
        print(f"\nOpen on your phone (same Wi-Fi):  http://{t.getsockname()[0]}:5000\n")
    except OSError:
        pass
    app.run(host="0.0.0.0", port=5000, threaded=True)
