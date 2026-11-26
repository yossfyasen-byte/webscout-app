# WebScout (App + Termux)

A simple Android app that gives a graphical interface to the [ZeroSpecter](https://github.com/AlmunharifHamoudi/zerospecter) scanner.
The scanner itself runs inside Termux. This is a modified version of the original tool.

> Use this tool only on websites you own or on sites you have written permission to test.

## How it works
- `termux/zs_server.py` is a small Python server (no external libraries) on `127.0.0.1:8765`. It starts scans and shows the reports.
- The Android app (`app/`) is a WebView that opens this server. It can start the server through Termux.
- `.github/workflows/build.yml` builds the APK on GitHub, so you do not need a computer.

## 1) Build the APK on GitHub (one time)
1. Upload this project to a new GitHub repository (branch `main`).
2. Open the **Actions** tab, then **Build APK**, then **Run workflow**.
3. When it finishes (a few minutes), open the run and download the **WebScout-apk** artifact (a zip that contains `app-debug.apk`).
4. Install the APK. You must allow installing apps from unknown sources.

If the build fails, open the error log and share it.

## 2) Set up Termux (once per device)
Install **Termux from F-Droid** (the old Google Play version does not work), then run:
```
pkg install -y git
git clone https://github.com/<your-name>/<your-repo>.git
bash <your-repo>/termux/setup_termux.sh
```
The script installs the packages and the scanner, and enables `allow-external-apps` so the app can start the server.
Installing the Python libraries (especially pydantic) can take a while.

If you have your own modified copy of the scanner on GitHub:
```
ZS_REPO=https://github.com/<your-name>/<your-scanner>.git bash <your-repo>/termux/setup_termux.sh
```

## 3) Usage
- Open the **WebScout** app. If the server is not running, tap **Start server** (it asks for permission once).
- **Scan** tab: enter the URL, choose the modules, confirm authorization, and start.
- Or start the server by hand: `cd ~/zerospecter-ui && python zs_server.py`, then open `127.0.0.1:8765` in any browser.

## Notes
- The server listens on `127.0.0.1` only and rejects requests from external sites.
- The scanner enforces its own scope and requires authorization. The interface does not bypass them.
- The original scanner is released under the MIT license. See its LICENSE file.
- If the "Start server" button does not work, check that `~/.termux/termux.properties` contains `allow-external-apps = true`, then run `termux-reload-settings`.
