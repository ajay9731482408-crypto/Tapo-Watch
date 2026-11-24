# Tapo Watch Android app

A small Android app that opens your Tapo Watch server. The camera work still runs on your computer.

## Get the APK (no Android Studio needed)
1. Push this whole folder to a GitHub repo (see the git steps in the main chat).
2. On GitHub open the **Actions** tab, choose **Build Android APK**, press **Run workflow**.
3. When it finishes (about 5 minutes), open the run and download **tapo-watch-apk**.
4. Unzip it, send `app-debug.apk` to your phone, open it, and allow "Install unknown apps" when asked.

## First launch
Type your computer's address, for example `192.168.1.25:5000`. It is remembered.
Away from home, install Tailscale on the phone and computer and use the computer's Tailscale address.
