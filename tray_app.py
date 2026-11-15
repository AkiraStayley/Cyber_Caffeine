"""
Cyber Caffeine: a minimal Windows system-tray client for a threat feed.

Security design
- Opens NO listening ports. Its only network activity is an HTTPS GET to feed_url.
- Treats everything it downloads as untrusted: size-capped, schema-checked,
  text is HTML-escaped, and links open only if they are https:// AND on an
  allowlisted host.
- Holds no API keys. The cloud job that builds the feed owns the Claude key.

Requires Python 3.10+ on Windows:
    pip install pystray pillow windows-toasts
Run without a console window:
    pythonw tray_app.py
On first run it creates %LOCALAPPDATA%\\CyberCaffeine\\config.json; put your feed URL there.
"""

import base64
import html
import json
import logging
import os
import threading
import urllib.request
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pystray
from PIL import Image, ImageDraw
from windows_toasts import Toast, WindowsToaster

# ------------------------------------------------------------------ settings
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "CyberCaffeine"
CONFIG_FILE = APP_DIR / "config.json"
STATE_FILE = APP_DIR / "seen.json"
REPORT_FILE = APP_DIR / "morning_report.html"
LOG_FILE = APP_DIR / "cyber_caffeine.log"

DEFAULTS = {
    "feed_url": "https://raw.githubusercontent.com/AkiraStayley/Cyber_Caffeine/main/feed/threat-feed.json",
    # Daily report notification, in this PC's local time (24h "HH:MM").
    # New vulnerabilities are held back and delivered together with it.
    "report_time": "08:05",
    # How often to check the feed. Major outages are notified on the first
    # check after they appear, so this sets how quickly you hear about them.
    "poll_minutes": 15,
    "max_toasts_per_poll": 5,
}

# Links in toasts and the report open only if they point at one of these hosts.
ALLOWED_LINK_HOSTS = {
    "nvd.nist.gov", "www.cisa.gov", "msrc.microsoft.com",
    "thehackernews.com",  # morning report headlines
    # government advisories
    "www.ncsc.gov.uk", "cert.europa.eu", "cyber.gc.ca", "www.cyber.gc.ca",
    # official status pages for outage alerts
    "status.cloud.microsoft", "health.aws.amazon.com", "status.cloud.google.com",
}

MAX_FEED_BYTES = 512 * 1024   # refuse anything bigger than 512 KB
MAX_ITEMS = 200               # per list; a normal feed has well under 20
MAX_URL = 500                 # characters; real links here are under 120
MAX_TEXT = 400                # truncate titles/details
MAX_SUMMARY = 20_000
MAX_SEEN = 5000


# ------------------------------------------------------------------ helpers
def load_config() -> dict:
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULTS, indent=2), encoding="utf-8")
    cfg = {**DEFAULTS, **json.loads(CONFIG_FILE.read_text(encoding="utf-8"))}
    if urlparse(cfg["feed_url"]).scheme != "https":
        raise ValueError("feed_url must start with https://")
    cfg["poll_minutes"] = max(5, int(cfg["poll_minutes"]))
    cfg["max_toasts_per_poll"] = max(1, int(cfg["max_toasts_per_poll"]))
    cfg["report_time"] = datetime.strptime(str(cfg["report_time"]), "%H:%M").time()
    return cfg


def safe_link(url) -> str | None:
    """Return url only if it's https, on an allowlisted host, with no tricks."""
    if not isinstance(url, str) or len(url) > MAX_URL:
        return None
    p = urlparse(url)
    if (p.scheme == "https" and p.hostname in ALLOWED_LINK_HOSTS
            and p.port is None and not p.username and not p.password):
        return url
    return None


def clean_text(value, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        return ""
    value = "".join(ch for ch in value if ch.isprintable() or ch == "\n")
    return value[:limit].strip()


def fetch_feed(url: str) -> dict:
    req = urllib.request.Request(
        url, headers={"User-Agent": "CyberCaffeine/1.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # TLS verified by default
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        if urlparse(resp.geturl()).scheme != "https":
            raise RuntimeError("redirected away from https")
        body = resp.read(MAX_FEED_BYTES + 1)
    if len(body) > MAX_FEED_BYTES:
        raise RuntimeError("feed too large")
    return json.loads(body.decode("utf-8"))


def validate_items(items) -> list[dict]:
    """Keep well-formed entries; drop anything without an id or a safe link."""
    valid = []
    for item in (items if isinstance(items, list) else [])[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        item_id = clean_text(item.get("id"), 64)
        link = safe_link(item.get("url"))
        if not item_id or not link:
            continue
        valid.append({
            "id": item_id,
            "title": clean_text(item.get("title")) or item_id,
            "detail": clean_text(item.get("detail")),
            "url": link,
            "action": clean_text(item.get("action"), 200),
            "ransomware": item.get("ransomware") is True,
        })
    return valid


def validate_feed(raw) -> dict:
    """Keep only well-formed fields; drop anything with an unsafe link."""
    if not isinstance(raw, dict):
        raise ValueError("feed is not a JSON object")
    report = raw.get("report") if isinstance(raw.get("report"), dict) else {}
    return {
        "generated_at": clean_text(raw.get("generated_at"), 40),
        "news": validate_items(raw.get("news")),
        "alerts": validate_items(raw.get("alerts")),
        "advisories": validate_items(raw.get("advisories")),
        "outages": validate_items(raw.get("outages")),
        "report_date": clean_text(report.get("date"), 10),
        "report_summary": clean_text(report.get("summary"), MAX_SUMMARY),
    }


def load_state() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return {"seen": [str(x) for x in data.get("seen", [])],
                "last_report": str(data.get("last_report", ""))}
    except (OSError, ValueError, AttributeError):
        return {"seen": [], "last_report": ""}


def save_state(state: dict) -> None:
    state["seen"] = state["seen"][-MAX_SEEN:]
    STATE_FILE.write_text(json.dumps(state), encoding="utf-8")


LOGO_FILE = Path(__file__).resolve().parent / "assets" / "logo_cup.jpg"

# Colours taken from logo v1.3: deep navy, cyan glow, alert red.
REPORT_CSS = """
:root{--bg:#07131c;--panel:#0d2230;--edge:#1c4256;--text:#d6eef3;--muted:#8fb3bf;
--cyan:#4ff0f0;--red:#ff5c50}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 "Segoe UI",sans-serif;
background-image:linear-gradient(rgba(79,240,240,.04) 1px,transparent 1px),
linear-gradient(90deg,rgba(79,240,240,.04) 1px,transparent 1px);background-size:32px 32px}
main{max-width:46rem;margin:0 auto;padding:2.5rem 1rem 3rem}
h1,h2{font-family:Consolas,"Cascadia Mono",monospace;font-weight:600;letter-spacing:.04em}
h1{color:var(--cyan);font-size:1.7rem;margin:0 0 .2rem;text-shadow:0 0 12px rgba(79,240,240,.45)}
h2{color:var(--cyan);font-size:1.05rem;text-transform:uppercase;margin:2.2rem 0 .8rem;
border-bottom:1px solid var(--edge);padding-bottom:.35rem}
h2.alert{color:var(--red);border-color:rgba(255,92,80,.4)}
.date{color:var(--muted);font-family:Consolas,monospace;margin:0}
.intro{white-space:pre-wrap;margin:0 0 1rem}
ul{list-style:none;padding:0;margin:0}
li{background:var(--panel);border:1px solid var(--edge);border-left:3px solid var(--cyan);
border-radius:4px;padding:.7rem 1rem;margin-bottom:.6rem}
li.outage,li.ransomware{border-left-color:var(--red)}
li.news{border-left-color:var(--muted)}
li.advisory{border-left-color:#f0b84f}
li small{color:var(--muted);display:block}
li .action{color:var(--text);font-size:.9rem;margin-top:.25rem}
.badge{display:inline-block;background:rgba(255,92,80,.15);color:var(--red);font-size:.75rem;
font-family:Consolas,monospace;border:1px solid rgba(255,92,80,.5);border-radius:3px;
padding:0 .4rem;margin-left:.5rem;vertical-align:middle}
a{color:var(--cyan);font-weight:600;text-decoration:none}
a:hover{text-decoration:underline}
footer{color:var(--muted);font-size:.8rem;margin-top:2.5rem;font-family:Consolas,monospace}
.corner{position:fixed;top:12px;width:110px;height:131px;background:var(--logo) center/cover;
border:1px solid var(--edge);border-radius:8px;box-shadow:0 0 18px rgba(79,240,240,.25);opacity:.9}
.tl{left:12px}.tr{right:12px}
@media (max-width:1100px){.corner{width:60px;height:72px;opacity:.35}}
"""


def logo_css() -> str:
    """The logo as an inline data URI, so the page loads nothing from outside."""
    try:
        data = base64.b64encode(LOGO_FILE.read_bytes()).decode("ascii")
    except OSError:
        return ".corner{display:none}"
    return f":root{{--logo:url(data:image/jpeg;base64,{data})}}"


def write_report(feed: dict) -> None:
    """Static local HTML; a CSP blocks all scripts and remote loads."""
    def card(a, cls=""):
        if a["ransomware"]:
            cls = "ransomware"
        badge = '<span class="badge">RANSOMWARE</span>' if a["ransomware"] else ""
        action = (f'<div class="action">Action: {html.escape(a["action"])}</div>'
                  if a["action"] else "")
        return (f'<li class="{cls}"><a href="{html.escape(a["url"])}">{html.escape(a["title"])}</a>'
                f'{badge}<small>{html.escape(a["detail"])}</small>{action}</li>')
    outages = (f'<h2 class="alert">Major outages now</h2>'
               f'<ul>{"".join(card(o, "outage") for o in feed["outages"])}</ul>'
               if feed["outages"] else
               '<h2>Major outages</h2>'
               '<p class="intro">There are no major outages at the moment.</p>')
    alerts = ("".join(card(a) for a in feed["alerts"])
              or "<li>No new actively exploited vulnerabilities.</li>")
    news = (f'<h2>Today\'s headlines</h2><ul>{"".join(card(n, "news") for n in feed["news"])}</ul>'
            if feed["news"] else "")
    advisories = (f'<ul>{"".join(card(a, "advisory") for a in feed["advisories"])}</ul>'
                  if feed["advisories"] else
                  '<p class="intro">There are no new government advisories in the last 48 hours.</p>')
    advisories = f'<h2>Government advisories</h2>{advisories}'
    summary = html.escape(feed["report_summary"])
    intro = f'<p class="intro">{summary}</p>' if summary else ""
    corners = "".join(f'<div class="corner {c}" aria-hidden="true"></div>' for c in ("tl", "tr"))
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber Caffeine report</title>
<style>{REPORT_CSS}{logo_css()}</style></head><body>
{corners}
<main>
<h1>Morning threat report</h1>
<p class="date">{html.escape(feed["report_date"] or "latest")}</p>
{news}
<h2>Exploited vulnerabilities</h2>
{intro}<ul>{alerts}</ul>
{advisories}
{outages}
<footer>Feed generated {html.escape(feed["generated_at"])}</footer>
</main>
</body></html>"""
    REPORT_FILE.write_text(page, encoding="utf-8")


def open_link(url: str) -> None:
    if safe_link(url):  # re-check at click time
        webbrowser.open(url)


ICON_FILE = Path(__file__).resolve().parent / "assets" / "tray.ico"
APP_NAME = "Cyber Caffeine"  # also the notification ID (AUMID) windows-toasts uses


def register_notification_icon() -> None:
    """Show the cup icon in the notification header. Windows looks it up under
    HKCU\\Software\\Classes\\AppUserModelId\\<AUMID>; per-user, no admin needed.
    To undo: delete that key."""
    try:
        import winreg
        key_path = rf"Software\Classes\AppUserModelId\{APP_NAME}"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
            if ICON_FILE.exists():
                winreg.SetValueEx(key, "IconUri", 0, winreg.REG_SZ, str(ICON_FILE))
    except OSError as exc:
        logging.warning("couldn't register notification icon: %s", exc)


def make_icon() -> Image.Image:
    """The cup icon from assets/ (made by tools/make_icon.py); a plain red
    shield if it's missing."""
    try:
        return Image.open(ICON_FILE)
    except OSError:
        pass
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon([(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)], fill=(200, 40, 40))
    d.rectangle([29, 18, 35, 38], fill="white")
    d.rectangle([29, 43, 35, 49], fill="white")
    return img


# ------------------------------------------------------------------ app
class CyberCaffeine:
    def __init__(self):
        self.cfg = load_config()
        self.state = load_state()
        register_notification_icon()
        self.toaster = WindowsToaster(APP_NAME)
        self.wake = threading.Event()
        self.stopping = threading.Event()
        self.icon = pystray.Icon(
            "CyberCaffeine", make_icon(), "Cyber Caffeine",
            menu=pystray.Menu(
                pystray.MenuItem("Open morning report", self.on_open_report, default=True),
                pystray.MenuItem("Check now", self.on_check_now),
                pystray.MenuItem("Quit", self.on_quit),
            ))

    def toast(self, title: str, body: str, on_click) -> None:
        t = Toast()
        t.text_fields = [title[:120], body[:200]]
        t.on_activated = lambda _args: on_click()
        self.toaster.show_toast(t)

    def open_report(self) -> None:
        if REPORT_FILE.exists():
            os.startfile(REPORT_FILE)  # opens in default browser

    def open_report_and_clear(self) -> None:
        """Clicking the report notification means you'll read it there, so
        the individual alert notifications behind it are dismissed."""
        self.open_report()
        try:
            self.toaster.clear_toasts()
        except Exception as exc:
            logging.warning("couldn't clear notifications: %s", exc)

    def report_time_today(self) -> datetime:
        return datetime.combine(datetime.now().date(), self.cfg["report_time"])

    def report_due(self, feed: dict) -> bool:
        """Today's report (built by the feed job earlier this morning), past
        report_time, and not shown yet."""
        today_utc = datetime.now(timezone.utc).date().isoformat()
        return (feed["report_date"] == today_utc
                and feed["report_date"] != self.state["last_report"]
                and datetime.now() >= self.report_time_today())

    def poll_once(self) -> None:
        try:
            feed = validate_feed(fetch_feed(self.cfg["feed_url"]))
        except Exception as exc:  # network, JSON, schema: log and try later
            logging.warning("poll failed: %s", exc)
            self.icon.title = "Cyber Caffeine (feed unreachable)"
            return
        self.icon.title = "Cyber Caffeine"
        write_report(feed)
        seen = set(self.state["seen"])

        if not self.state["seen"] and not self.state["last_report"]:
            # first launch: remember what's already out there instead of flooding
            self.state["seen"] += [a["id"] for a in feed["outages"] + feed["advisories"] + feed["alerts"]]
            self.state["last_report"] = feed["report_date"]
            save_state(self.state)
            self.toast("Cyber Caffeine is running",
                       f"Daily report at {self.cfg['report_time']:%H:%M}. "
                       "Major outages are notified as they happen.", self.open_report)
            return

        new_outages = [o for o in feed["outages"] if o["id"] not in seen]
        report_due = self.report_due(feed)

        # Daily report: its notification always comes first; clicking it opens
        # the report and clears everything after it, outages included.
        new_alerts = []
        if report_due:
            # government advisories first: they're usually the earliest warning
            new_alerts = [a for a in feed["advisories"] + feed["alerts"] if a["id"] not in seen]
            n_vulns = sum(not a["id"].startswith("adv-") for a in new_alerts)
            n_adv = len(new_alerts) - n_vulns
            parts = [f"{len(feed['news'])} headlines"] if feed["news"] else []
            parts.append(f"{n_vulns} exploited {'vulnerability' if n_vulns == 1 else 'vulnerabilities'}")
            if n_adv:
                parts.append(f"{n_adv} government {'advisory' if n_adv == 1 else 'advisories'}")
            if feed["outages"]:
                parts.append(f"{len(feed['outages'])} major outage(s)")
            self.toast("Morning threat report ready", ", ".join(parts) + ". Click to read it.",
                       self.open_report_and_clear)

        # Major outages: straight away (after the report notification if one is due).
        for o in new_outages:
            self.toast(o["title"], o["detail"] or "Click for the status page",
                       lambda u=o["url"]: open_link(u))

        # New advisories and vulnerabilities, one by one, only with the daily report.
        limit = self.cfg["max_toasts_per_poll"]
        for a in new_alerts[:limit]:
            self.toast(a["title"], a["detail"] or "Click for details",
                       lambda u=a["url"]: open_link(u))
        if len(new_alerts) > limit:
            self.toast(f"{len(new_alerts) - limit} more new alerts",
                       "They're all in the report", self.open_report_and_clear)

        self.state["seen"] += [x["id"] for x in new_outages + new_alerts]
        if report_due:
            self.state["last_report"] = feed["report_date"]
        save_state(self.state)

    def seconds_until_next_check(self) -> float:
        """Normally poll_minutes, but wake up exactly at report_time if that's sooner."""
        wait = self.cfg["poll_minutes"] * 60
        until_report = (self.report_time_today() - datetime.now()).total_seconds()
        if 0 < until_report < wait:
            wait = until_report + 1
        return wait

    def poll_loop(self) -> None:
        while not self.stopping.is_set():
            self.poll_once()
            self.wake.wait(self.seconds_until_next_check())
            self.wake.clear()

    # tray menu callbacks
    def on_open_report(self, icon, item):
        self.open_report()

    def on_check_now(self, icon, item):
        self.wake.set()

    def on_quit(self, icon, item):
        self.stopping.set()
        self.wake.set()
        icon.stop()

    def run(self) -> None:
        threading.Thread(target=self.poll_loop, daemon=True).start()
        self.icon.run()  # blocks on the main thread


if __name__ == "__main__":
    APP_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    CyberCaffeine().run()
