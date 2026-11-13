<p align="center">
  <img src="assets/logo.jpg" alt="Cyber Caffeine logo" width="720">
</p>

<p align="center">
  A Windows tray app that gives you one short cyber-security report each morning,
  and tells you straight away when Microsoft 365, AWS or Google Cloud has a major outage.
</p>

---

## What you get

### Morning report

At 08:05 each day (you can change the time) a report opens in your browser with four sections:

1. Today's headlines: the top 2 stories from The Hacker News.
2. Exploited vulnerabilities: flaws that attackers are known to be using right now, from CISA's Known Exploited Vulnerabilities catalogue. Each one shows what's affected and what to do. Anything used by ransomware gangs is tagged and listed first.
3. Government advisories: serious alerts from the UK's NCSC, CERT-EU and the Canadian Centre for Cyber Security. These often arrive days before a flaw reaches CISA's list. For a PHP flaw in October 2026, the NCSC warned on the day it went public and CISA listed it five days later.
4. Major outages: any big Microsoft 365, AWS or Google Cloud outage that is still going on.

Every item links to its source.

### Notifications

At report time, "Morning threat report ready" comes first, followed by one notification per new government advisory and vulnerability. Click the report notification to read everything in one place, and the rest are cleared for you. Close it instead if you'd rather go through them one by one.

Major outages are notified as soon as they're spotted, at any time of day. Minor or partial problems are left out, as is anything that started more than 48 hours ago.

## How it works

```
GitHub Actions, in this repo (runs on a schedule, free)
  ├─ twice an hour: checks CISA, NCSC, CERT-EU, the Canadian Centre,
  │                 Microsoft 365, AWS and Google Cloud
  └─ once a day:    also fetches headlines and writes the briefing
        │
        ▼
  feed/threat-feed.json   (one small file, committed only when something changes)
        ▲
        │  your PC downloads this one file every 15 minutes
        │
Windows PC: tray_app.py
  ├─ major outage                 → notification straight away
  └─ report time (08:05 default)  → report notification, then each new advisory and vulnerability
```

Your PC only ever talks to one address (GitHub), opens no ports and stores no passwords or keys. All the gathering happens in GitHub Actions.

## Install

You need Windows 10 or 11. No admin rights are needed; everything installs for your user only.

### Quick install

1. On this page, click **Code → Download ZIP**, and extract it somewhere permanent inside your user folder, for example `Documents\Cyber_Caffeine`. (Or `git clone` the repo.)
2. Open PowerShell in that folder and run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1
   ```

The script installs Python 3.14 if you don't already have 3.10 or newer, installs the libraries the app needs (at fixed, tested versions, each checked against its published fingerprint), sets the app to start when you sign in, and starts it.

You'll see the cup in the system tray (it may be hidden under the **^** arrow) and a single "Cyber Caffeine is running" notification. Existing items aren't notified on first launch, so you won't get a flood. Your first report notification comes with the next new daily report (usually the next morning); double-click the tray icon to read the current one straight away.

Don't want it to start at sign-in? Add `-NoStartup`.

> Windows blocks downloaded PowerShell scripts by default. `-ExecutionPolicy Bypass` lets this one run without changing the setting for anything else. The script is short, so it's worth reading first.

### Manual install

```powershell
winget install Python.Python.3.14        # then open a new PowerShell window
cd $HOME\Documents\Cyber_Caffeine
py -m pip install --require-hashes --only-binary :all: -r requirements.txt
pythonw tray_app.py                      # pythonw = no console window
```

To start it at sign-in, press **Win+R**, type `shell:startup`, and create a shortcut there to:

```
"%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe" "%USERPROFILE%\Documents\Cyber_Caffeine\tray_app.py"
```

Keep the folder where it is afterwards: the app loads its icons from `assets\`.

Put it inside your own user folder (Documents is ideal), not somewhere like `C:\Cyber_Caffeine`. Folders made directly under `C:\` can be changed by other accounts on the same PC, and the app runs as you every time you sign in.

## Using it

Double-click the tray icon to open the latest report. Right-click it for Open morning report, Check now and Quit.

Settings are in `%LOCALAPPDATA%\CyberCaffeine\config.json`, created on first run. Quit the app from the tray and start it again after editing.

| Setting | Default | What it does |
|---|---|---|
| `report_time` | `"08:05"` | When the morning report notification appears, in your PC's local time (24-hour). Follows the clocks changing automatically. |
| `poll_minutes` | `15` | How often the app checks for new outages (minimum 5). The check is one small download. |
| `max_toasts_per_poll` | `5` | Most vulnerability notifications shown at once; any extra are summed up in one. |
| `feed_url` | this repo's feed | Where the app gets its data. Change it only if you run your own feed (see below). |

The same folder holds the latest report (`morning_report.html`), a log (`cyber_caffeine.log`) and the list of items you've already been told about (`seen.json`).

To update, download a fresh ZIP (or `git pull`) and run `install.ps1` again. It stops the running copy and starts the new one.

To uninstall:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
```

This stops the app and removes the sign-in shortcut and the notification registration. Delete `%LOCALAPPDATA%\CyberCaffeine` as well to remove your settings, then delete the app folder.

## Troubleshooting

| Problem | Fix |
|---|---|
| No notifications | Check Windows Do not disturb / Focus is off, and that notifications are allowed for "Cyber Caffeine" in Settings → System → Notifications. |
| Tray tooltip says "feed unreachable" | Check your internet connection. If it persists, open the `feed_url` from `config.json` in a browser; the log file has the exact error. |
| No cup icon on notifications | Windows caches notification icons. Quit and restart the app; signing out and back in clears the cache for certain. |
| Report didn't arrive at report time | The report is built early each morning by GitHub Actions. If that run was late, the notification follows on the next check (within 15 minutes of it finishing). Check the repo's **Actions** tab for failed runs. |
| Want to see it working without waiting | Right-click the tray icon → **Check now**, or double-click it to open the current report. |

## Running your own feed

By default every install reads this repo's feed. To run your own (for example, to change the schedule or sources):

1. Fork this repo. Scheduled workflows don't run in forks until you enable them: open the fork's **Actions** tab and turn workflows on.
2. Optional: under **Settings → Secrets and variables → Actions**:
   - add the secret `ANTHROPIC_API_KEY` to have Claude write a short briefing paragraph each morning (about 10¢ a month; without it you get a one-line summary instead);
   - add the variable `WATCH`, e.g. `microsoft,fortinet,cisco`, to only get vulnerabilities for those vendors. On a public repo this shows everyone which products you use, so leave it out if that matters.
3. In **Actions → Build threat feed → Run workflow**, run it once with mode `report` to create the feed file.
4. Set `feed_url` in your `config.json` to
   `https://raw.githubusercontent.com/<your-username>/Cyber_Caffeine/main/feed/threat-feed.json`.

The schedule is in [.github/workflows/threat-feed.yml](.github/workflows/threat-feed.yml) (times in UTC). The morning run is at 06:23 UTC so the report is ready well before 08:05 UK time all year round; GitHub can start scheduled runs 30+ minutes late, so leave a margin if you move it.

GitHub turns off scheduled workflows in public repos after 60 days without activity. The feed's own commits normally count, but it's worth checking the Actions tab now and then.

## Cost

Nothing, unless you add the optional Claude briefing (about 10¢ a month). The sources cost nothing to use, and GitHub Actions is free for public repos.

## Security

### On your PC

The app opens no network ports and holds no secrets. Its only network traffic is the HTTPS download of the feed. It treats that feed as untrusted: the download is size-capped and checked field by field, and all text is escaped before display. Links open only if they're HTTPS and on a fixed allowlist (NVD, CISA, the NCSC, CERT-EU, the Canadian Centre, the Microsoft, AWS and Google Cloud status pages, The Hacker News), and they're checked again when you click. The report page blocks all scripts and loads nothing from the internet.

### In GitHub Actions

The builder uses only Python's standard library, so the workflow installs nothing. Links are built in code from validated IDs and never taken from the AI. If you add an API key, only the step that needs it can see it. Pull requests can't trigger the workflow. The one action it uses, `actions/checkout`, is pinned to an exact commit.

### Libraries

`requirements.txt` pins each library to the version it was tested with, along with the SHA-256 fingerprint of every Windows build of that version. The installer refuses any download that doesn't match and never compiles anything from source. To upgrade a library, change its version and run `python tools/hash_requirements.py requirements.txt`.

### Your GitHub account

Whoever controls the repo controls what appears on screen for everyone using its feed, so protect the account with a passkey or two-factor authentication.

## Sources

| What | Source |
|---|---|
| Headlines | [The Hacker News](https://thehackernews.com/) |
| Exploited vulnerabilities | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Government advisories | [NCSC (UK)](https://www.ncsc.gov.uk/) security news, [CERT-EU](https://cert.europa.eu/publications/security-advisories/) advisories, [Canadian Centre for Cyber Security](https://www.cyber.gc.ca/en/alerts-advisories) alerts |
| Outages | [Microsoft 365 status](https://status.cloud.microsoft/), [AWS Health Dashboard](https://health.aws.amazon.com/health/status), [Google Cloud status](https://status.cloud.google.com/) |

## License

[MIT](LICENSE)
