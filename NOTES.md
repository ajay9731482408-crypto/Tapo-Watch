# Tapo Watch: project notes

Paste or upload this file at the start of a new chat. Claude has no memory between chats, so this is the memory.
Last updated: 2026-11-25. No passwords or keys are stored here.

## What it is
Self-hosted camera site (Flask + OpenCV) that runs on the user's computer, plus an Android wrapper app.
User has: a **Tapo** camera (moves) and a **CP Plus** camera (fixed, no motor). Wants it usable from a phone.

## Files (folder `tapo_watch/`)
- `app.py`: the whole server and website (one file; HTML/CSS/JS are Python strings inside it)
- `requirements.txt`: flask, opencv-python, requests, pytapo
- `.gitignore`: keeps settings.json (camera passwords), recordings, snaps, events.json, security.log out of GitHub
- `branding/`: logo master `tapo-watch-logo.svg`, HD PNGs (1024, 2048). Logo = gold shield with a camera lens on a dark teal tile.
- `static/`: icon-192/512.png and favicon (home-screen and PWA icons, served by app.py)
- `autostart/`: `install_windows.bat`, `start_tapo_watch.bat`, `install_linux.sh` (start on boot, restart if it stops)
- `android_app/` (icon + splash sources in `assets/`; the workflow runs `capacitor-assets generate --android`): Capacitor wrapper (asks for server address like 192.168.1.25:5000, remembers it, opens it)
- `.github/workflows/build-apk.yml`: GitHub Actions builds `app-debug.apk` (Run workflow, download artifact `tapo-watch-apk`)
- Runtime files made by the app: settings.json, events.json, security.log, recordings/, snaps/

## Run
`pip install -r requirements.txt`, `python app.py`, open http://localhost:5000, create password on first visit.
Phone on same Wi-Fi: address is printed at startup. Away from home: Tailscale on phone and computer.

## Features built
- Multi-camera (add/edit/remove in Settings). Brands: Tapo, CP Plus/Dahua, CP Plus older (port 5543), Hikvision, Reolink, Other (paste RTSP, use {user} and {pass}).
- RTSP patterns: tapo `554/stream1|stream2`; cpplus `554/cam/realmonitor?channel=1&subtype=0|1`; cpplus2 `5543/live/channel1`; hikvision `554/Streaming/Channels/101|102`; reolink `554/h264Preview_01_main|sub`. Special characters in logins are URL-escaped.
- Test connection, Find brand (tries 5 addresses; warns about camera lockout from wrong logins).
- Detection: motion (OpenCV MOG2), faces (Haar cascade), sensitivity, overlays on/off, brighten dark video (CLAHE), arm schedule.
- Smart follow = software zoom that tracks movement (works on any camera, used for the fixed CP Plus).
- Tapo-only (via pytapo): night vision auto/day/night, auto-track (motor), siren, privacy, status light, person detection, tamper alert, flip, restart, move pad, Detect features.
- Picture adjust per camera: brightness, contrast, colour, rotate, mirror.
- Recording on motion/face, 5-minute pieces, events with snapshots, clip download/delete, snapshot button.
- Storage: daily clean-up at a set time repeating every N days, keep N days, size cap, next run shown. Cloud backup through rclone (any remote). SD card is recorded by the camera itself (set in Tapo app), not controlled here.
- Alerts: Telegram photo on event, offline alert after 60 s, back-online message.
- Outage: cameras auto-reconnect, settings re-applied after outage (`restore`), camera thread supervisor, half-written clips deleted at startup.
- UI: dark/light/auto theme, modern line icons, mobile bottom tabs, installable PWA.
- Security: password hash, lockout (5 tries/5 min), optional 2FA (TOTP, own code), sign out everywhere, 12 h sessions, SameSite Strict, Origin check + JSON-only API writes, 240 requests/min limit, security headers + CSP, LAN/VPN-only by default (`lan_only`), settings.json chmod 600, activity log in Settings.

## Not built / limits
- **Talking through the camera (two-way audio): not built.** No reliable way found. Use the Tapo / CP Plus apps.
- Siren, tracking, night vision, features need `pytapo` and a camera that allows it. A Jan 2026 report says Tapo firmware 1.5.x may block pytapo. Video, recording and Smart follow don't need pytapo.
- Never tested on real cameras (sandbox has no network). Unverified: pytapo values for night mode (`auto`/`off`/`on`), `moveMotor`, `setAutoTrackTarget`, feature probes; Hikvision/Reolink URL patterns.
- Camera passwords are stored in plain text in settings.json (file is user-only).
- Debug APK only. Google Play would need a signed release build and a developer account.

## Cloud storage (free tiers from 2026 comparisons, all work with rclone)
MEGA 20 GB (encrypted) mega.io; Google Drive 15 GB drive.google.com; pCloud up to 10 GB pcloud.com; Koofr 10 GB koofr.eu; Filen 10 GB (encrypted) filen.io; Icedrive 10 GB icedrive.net; Proton Drive 5 GB proton.me/drive; OneDrive 5 GB onedrive.live.com. TeraBox 1 TB exists but rclone doesn't support it and privacy is weak. rclone: rclone.org/downloads

## Lessons for editing `app.py` (saves debugging time)
- The page is rendered with Jinja (`render_template_string`): never write `{{`, `{%`, `{#` in the HTML/JS.
- The page is a normal Python string: a backslash-quote (`\'`) in JS gets eaten. Use `&quot;` or helper functions, and `[0-9]` instead of `\d`.
- `create_file` fails on existing paths; patch with Python `str.replace` + `assert count == 1`.
- After patching: `python3 -m py_compile app.py`, then Flask test client, then extract the page `<script>` and run `node --check`.
- The sandbox's OpenCV can't find the face cascade file (harmless in tests).

## Tools / accounts status
- Bitrise connector: **connected**. Workspace slug `009241c48ea2165e`. No Bitrise app registered yet.
- To build via Bitrise Claude needs a **GitHub repo URL** (and Bitrise linked to GitHub). Free alternative already in the repo: GitHub Actions workflow.
- Claude cannot create the GitHub repo or push code. User runs: `git init`, `git add .`, `git commit -m "Tapo Watch"`, `git branch -M main`, `git remote add origin <repo url>`, `git push -u origin main`.
- Expo connector was offered but is not a good fit (React Native only).

## User preferences
Simple plain language, mobile-friendly short answers, wants it as an Android app, wants GitHub, free tools, security-focused.

## Next steps
1. User pushes the folder to GitHub and shares the repo URL.
2. Either run the GitHub Actions workflow, or register the repo on Bitrise (`register_app`, then `finish_bitrise_app` with project type `other` and an Android stack, then `trigger_bitrise_build`) and fetch the APK with `list_artifacts`.
3. Test on real cameras; fix any pytapo errors using the exact error text.
4. Optional: app icon, signed release build, presets for Tapo motor cameras, Windows .exe.
