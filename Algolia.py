#!/usr/bin/env python3
"""
Algolia Index Export GUI

Authorized-use only:
Use this against Algolia applications and indices you own or have permission to export.

What it does:
- Lets you enter Algolia App ID, Search/Browse API key, index name, query, filters.
- Tries Algolia Browse API first if selected.
- Falls back to normal Search API pagination if Browse is unavailable.
- Saves records to JSONL, JSON array, or CSV.

Notes:
- Browse API requires the `browse` ACL.
- Search-only keys can use the search endpoint, but normal search pagination is often limited
  by the index's pagination settings, commonly 1,000 accessible hits unless configured otherwise.
"""

from __future__ import annotations

import csv
import json
import queue
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_TITLE = "Algolia Index Exporter"
USER_AGENT = "AlgoliaIndexExporterTk/1.0"


@dataclass
class ExportConfig:
    app_id: str
    api_key: str
    index_name: str
    query: str
    filters: str
    attributes_to_retrieve: str
    mode: str
    hits_per_request: int
    max_records: int
    sleep_seconds: float
    output_path: Path
    output_format: str
    strip_algolia_metadata: bool


class AlgoliaHTTPError(Exception):
    def __init__(self, status: int, body: str, url: str):
        super().__init__(f"HTTP {status}: {body[:500]}")
        self.status = status
        self.body = body
        self.url = url


def clean_app_id(app_id: str) -> str:
    return app_id.strip().replace("https://", "").replace("http://", "").split(".")[0].split("-dsn")[0].upper()


def algolia_post(app_id: str, api_key: str, endpoint: str, body: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    """
    POST JSON to an Algolia Search API endpoint.

    endpoint example:
      /1/indexes/products/query
      /1/indexes/products/browse
    """
    app_id = clean_app_id(app_id)
    base_urls = [
        f"https://{app_id}-dsn.algolia.net",
        f"https://{app_id}.algolia.net",
        f"https://{app_id}-1.algolianet.com",
        f"https://{app_id}-2.algolianet.com",
        f"https://{app_id}-3.algolianet.com",
    ]

    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    last_error: Optional[Exception] = None

    for base_url in base_urls:
        url = base_url + endpoint
        req = urllib.request.Request(
            url=url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "X-Algolia-Application-Id": app_id,
                "X-Algolia-API-Key": api_key,
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            # 4xx means credentials/permissions/request are wrong; don't retry all hosts endlessly.
            if 400 <= e.code < 500 and e.code != 429:
                raise AlgoliaHTTPError(e.code, body_text, url)
            last_error = AlgoliaHTTPError(e.code, body_text, url)
            # Rate limit / server-ish issues: try next host after a small pause.
            time.sleep(0.5)
        except Exception as e:
            last_error = e
            time.sleep(0.25)

    if last_error:
        raise last_error
    raise RuntimeError("Unknown Algolia request failure")


def parse_attributes(value: str) -> Optional[List[str]]:
    value = value.strip()
    if not value:
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


def build_common_params(cfg: ExportConfig) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "query": cfg.query,
        "hitsPerPage": max(1, min(cfg.hits_per_request, 1000)),
    }

    if cfg.filters.strip():
        params["filters"] = cfg.filters.strip()

    attrs = parse_attributes(cfg.attributes_to_retrieve)
    if attrs:
        params["attributesToRetrieve"] = attrs

    return params


def strip_metadata(record: Dict[str, Any]) -> Dict[str, Any]:
    # Keep objectID because it is normally the stable primary key.
    drop_prefixes = ("_highlightResult", "_snippetResult", "_rankingInfo")
    drop_exact = {"_distinctSeqID"}
    return {k: v for k, v in record.items() if k not in drop_exact and k not in drop_prefixes}


def export_browse(cfg: ExportConfig, log, progress, stop_event: threading.Event) -> Tuple[List[Dict[str, Any]], str]:
    """
    Browse export. Needs browse ACL. Uses cursor until Algolia stops returning one.
    """
    records: List[Dict[str, Any]] = []
    endpoint = f"/1/indexes/{urllib.parse.quote(cfg.index_name, safe='')}/browse"

    body = build_common_params(cfg)
    body["hitsPerPage"] = max(1, min(cfg.hits_per_request, 1000))

    cursor: Optional[str] = None
    page_count = 0

    while not stop_event.is_set():
        if cursor:
            body = {"cursor": cursor}

        data = algolia_post(cfg.app_id, cfg.api_key, endpoint, body)
        hits = data.get("hits", [])
        if not isinstance(hits, list):
            hits = []

        for hit in hits:
            if isinstance(hit, dict):
                records.append(strip_metadata(hit) if cfg.strip_algolia_metadata else hit)
                if cfg.max_records and len(records) >= cfg.max_records:
                    progress(len(records), None, "Max records reached")
                    return records, "browse"

        page_count += 1
        cursor = data.get("cursor")
        progress(len(records), None, f"Browse page {page_count}, got {len(hits)} hits")

        if not cursor:
            break

        if cfg.sleep_seconds > 0:
            time.sleep(cfg.sleep_seconds)

    return records, "browse"


def export_search(cfg: ExportConfig, log, progress, stop_event: threading.Event) -> Tuple[List[Dict[str, Any]], str]:
    """
    Search export via normal search pagination. Works with search-only keys.
    Caveat: accessible result count is capped by index pagination settings.
    """
    records: List[Dict[str, Any]] = []
    endpoint = f"/1/indexes/{urllib.parse.quote(cfg.index_name, safe='')}/query"

    page = 0
    nb_pages: Optional[int] = None
    nb_hits: Optional[int] = None

    while not stop_event.is_set():
        params = build_common_params(cfg)
        params["page"] = page
        params["hitsPerPage"] = max(1, min(cfg.hits_per_request, 1000))

        data = algolia_post(cfg.app_id, cfg.api_key, endpoint, params)
        hits = data.get("hits", [])
        if not isinstance(hits, list):
            hits = []

        nb_pages = int(data.get("nbPages", 0) or 0)
        nb_hits = int(data.get("nbHits", 0) or 0)

        for hit in hits:
            if isinstance(hit, dict):
                records.append(strip_metadata(hit) if cfg.strip_algolia_metadata else hit)
                if cfg.max_records and len(records) >= cfg.max_records:
                    progress(len(records), nb_hits, "Max records reached")
                    return records, "search"

        progress(len(records), nb_hits, f"Search page {page + 1}/{nb_pages or '?'} got {len(hits)} hits")

        page += 1
        if not hits or (nb_pages is not None and page >= nb_pages):
            break

        if cfg.sleep_seconds > 0:
            time.sleep(cfg.sleep_seconds)

    return records, "search"


def flatten_for_csv(value: Any, prefix: str = "") -> Dict[str, Any]:
    """
    Flatten nested dict/list values into CSV-friendly columns.
    Lists and complex values become compact JSON strings.
    """
    out: Dict[str, Any] = {}

    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(flatten_for_csv(v, key))
            elif isinstance(v, list):
                out[key] = json.dumps(v, ensure_ascii=False, separators=(",", ":"))
            else:
                out[key] = v
    else:
        out[prefix or "value"] = value

    return out


def save_records(records: List[Dict[str, Any]], path: Path, fmt: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = fmt.lower()

    if fmt == "jsonl":
        with path.open("w", encoding="utf-8", newline="\n") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        return

    if fmt == "json":
        with path.open("w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        return

    if fmt == "csv":
        flat = [flatten_for_csv(r) for r in records]
        fieldnames = sorted({key for row in flat for key in row.keys()})
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(flat)
        return

    raise ValueError(f"Unsupported format: {fmt}")


class AlgoliaExporterGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("860x690")
        self.minsize(760, 600)

        self.worker: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.messages: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

        self.var_app_id = tk.StringVar()
        self.var_api_key = tk.StringVar()
        self.var_show_key = tk.BooleanVar(value=False)
        self.var_index = tk.StringVar()
        self.var_query = tk.StringVar(value="")
        self.var_filters = tk.StringVar(value="")
        self.var_attrs = tk.StringVar(value="")
        self.var_mode = tk.StringVar(value="Auto: browse then search fallback")
        self.var_hits = tk.StringVar(value="1000")
        self.var_max_records = tk.StringVar(value="0")
        self.var_sleep = tk.StringVar(value="0.15")
        self.var_output = tk.StringVar(value=str(Path.cwd() / "algolia_export.jsonl"))
        self.var_format = tk.StringVar(value="jsonl")
        self.var_strip_meta = tk.BooleanVar(value=True)
        self.var_status = tk.StringVar(value="Idle")

        self._build_ui()
        self.after(100, self._poll_messages)

    def _build_ui(self):
        pad = {"padx": 10, "pady": 5}

        outer = ttk.Frame(self)
        outer.pack(fill="both", expand=True)

        form = ttk.LabelFrame(outer, text="Connection and export settings")
        form.pack(fill="x", **pad)

        for i in range(4):
            form.columnconfigure(i, weight=1)

        ttk.Label(form, text="App ID").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(form, textvariable=self.var_app_id).grid(row=0, column=1, columnspan=3, sticky="ew", **pad)

        ttk.Label(form, text="API Key").grid(row=1, column=0, sticky="w", **pad)
        self.api_entry = ttk.Entry(form, textvariable=self.var_api_key, show="•")
        self.api_entry.grid(row=1, column=1, columnspan=2, sticky="ew", **pad)
        ttk.Checkbutton(form, text="Show", variable=self.var_show_key, command=self._toggle_key).grid(row=1, column=3, sticky="w", **pad)

        ttk.Label(form, text="Index name").grid(row=2, column=0, sticky="w", **pad)
        ttk.Entry(form, textvariable=self.var_index).grid(row=2, column=1, columnspan=3, sticky="ew", **pad)

        ttk.Label(form, text="Query").grid(row=3, column=0, sticky="w", **pad)
        ttk.Entry(form, textvariable=self.var_query).grid(row=3, column=1, columnspan=3, sticky="ew", **pad)

        ttk.Label(form, text="Filters").grid(row=4, column=0, sticky="w", **pad)
        ttk.Entry(form, textvariable=self.var_filters).grid(row=4, column=1, columnspan=3, sticky="ew", **pad)

        ttk.Label(form, text="Attributes to retrieve").grid(row=5, column=0, sticky="w", **pad)
        ttk.Entry(form, textvariable=self.var_attrs).grid(row=5, column=1, columnspan=3, sticky="ew", **pad)
        ttk.Label(form, text="Comma separated. Leave blank for all retrievable attributes.").grid(row=6, column=1, columnspan=3, sticky="w", padx=10)

        ttk.Label(form, text="Mode").grid(row=7, column=0, sticky="w", **pad)
        ttk.Combobox(
            form,
            textvariable=self.var_mode,
            values=[
                "Auto: browse then search fallback",
                "Browse only (needs browse ACL)",
                "Search only (search-only key)",
            ],
            state="readonly",
        ).grid(row=7, column=1, columnspan=3, sticky="ew", **pad)

        ttk.Label(form, text="Hits/request").grid(row=8, column=0, sticky="w", **pad)
        ttk.Entry(form, textvariable=self.var_hits, width=12).grid(row=8, column=1, sticky="w", **pad)

        ttk.Label(form, text="Max records").grid(row=8, column=2, sticky="e", **pad)
        ttk.Entry(form, textvariable=self.var_max_records, width=12).grid(row=8, column=3, sticky="w", **pad)

        ttk.Label(form, text="Sleep between calls").grid(row=9, column=0, sticky="w", **pad)
        ttk.Entry(form, textvariable=self.var_sleep, width=12).grid(row=9, column=1, sticky="w", **pad)

        ttk.Checkbutton(
            form,
            text="Strip Algolia highlight/snippet/ranking metadata",
            variable=self.var_strip_meta,
        ).grid(row=9, column=2, columnspan=2, sticky="w", **pad)

        out = ttk.LabelFrame(outer, text="Output")
        out.pack(fill="x", **pad)
        out.columnconfigure(1, weight=1)

        ttk.Label(out, text="File").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(out, textvariable=self.var_output).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(out, text="Browse...", command=self._choose_output).grid(row=0, column=2, **pad)

        ttk.Label(out, text="Format").grid(row=1, column=0, sticky="w", **pad)
        ttk.Combobox(out, textvariable=self.var_format, values=["jsonl", "json", "csv"], state="readonly", width=12).grid(row=1, column=1, sticky="w", **pad)

        actions = ttk.Frame(outer)
        actions.pack(fill="x", **pad)

        self.btn_start = ttk.Button(actions, text="Start export", command=self._start)
        self.btn_start.pack(side="left", padx=5)

        self.btn_stop = ttk.Button(actions, text="Stop", command=self._stop, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        ttk.Label(actions, textvariable=self.var_status).pack(side="right", padx=5)

        self.progress = ttk.Progressbar(outer, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=5)

        log_frame = ttk.LabelFrame(outer, text="Log")
        log_frame.pack(fill="both", expand=True, **pad)

        self.log_text = tk.Text(log_frame, height=16, wrap="word")
        self.log_text.pack(side="left", fill="both", expand=True)

        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scroll.set)

        self._log("Enter App ID, API key, and index name. Blank query attempts to retrieve broadly, subject to key/index restrictions.")
        self._log("Tip: Use Browse mode with a key that has browse ACL for proper full exports. Search-only mode may be capped by pagination settings.")

    def _toggle_key(self):
        self.api_entry.configure(show="" if self.var_show_key.get() else "•")

    def _choose_output(self):
        fmt = self.var_format.get()
        ext = "." + fmt
        filename = filedialog.asksaveasfilename(
            title="Save export",
            defaultextension=ext,
            filetypes=[
                ("JSON Lines", "*.jsonl"),
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("All files", "*.*"),
            ],
        )
        if filename:
            self.var_output.set(filename)

    def _log(self, msg: str):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {msg}\n")
        self.log_text.see("end")

    def _validate_config(self) -> ExportConfig:
        app_id = self.var_app_id.get().strip()
        api_key = self.var_api_key.get().strip()
        index_name = self.var_index.get().strip()
        output_path = Path(self.var_output.get().strip())

        if not app_id:
            raise ValueError("App ID is required.")
        if not api_key:
            raise ValueError("API key is required.")
        if not index_name:
            raise ValueError("Index name is required.")
        if not output_path:
            raise ValueError("Output file is required.")

        try:
            hits = int(self.var_hits.get().strip())
        except ValueError:
            raise ValueError("Hits/request must be an integer.")

        if hits < 1:
            raise ValueError("Hits/request must be at least 1.")
        if hits > 1000:
            hits = 1000

        try:
            max_records = int(self.var_max_records.get().strip())
        except ValueError:
            raise ValueError("Max records must be an integer. Use 0 for no manual cap.")

        if max_records < 0:
            raise ValueError("Max records cannot be negative.")

        try:
            sleep_seconds = float(self.var_sleep.get().strip())
        except ValueError:
            raise ValueError("Sleep between calls must be a number.")

        if sleep_seconds < 0:
            raise ValueError("Sleep between calls cannot be negative.")

        return ExportConfig(
            app_id=app_id,
            api_key=api_key,
            index_name=index_name,
            query=self.var_query.get(),
            filters=self.var_filters.get(),
            attributes_to_retrieve=self.var_attrs.get(),
            mode=self.var_mode.get(),
            hits_per_request=hits,
            max_records=max_records,
            sleep_seconds=sleep_seconds,
            output_path=output_path,
            output_format=self.var_format.get(),
            strip_algolia_metadata=self.var_strip_meta.get(),
        )

    def _start(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning(APP_TITLE, "Export is already running.")
            return

        try:
            cfg = self._validate_config()
        except Exception as e:
            messagebox.showerror(APP_TITLE, str(e))
            return

        self.stop_event.clear()
        self.progress.configure(value=0, maximum=100)
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.var_status.set("Running")
        self._log("Starting export...")

        self.worker = threading.Thread(target=self._worker_main, args=(cfg,), daemon=True)
        self.worker.start()

    def _stop(self):
        self.stop_event.set()
        self.var_status.set("Stopping...")
        self._log("Stop requested. Finishing current request...")

    def _worker_main(self, cfg: ExportConfig):
        def log(msg: str):
            self.messages.put(("log", msg))

        def progress(count: int, total: Optional[int], status: str):
            self.messages.put(("progress", (count, total, status)))

        try:
            records: List[Dict[str, Any]]
            used_mode: str

            mode = cfg.mode.lower()
            if mode.startswith("browse only"):
                log("Using Browse API only.")
                records, used_mode = export_browse(cfg, log, progress, self.stop_event)

            elif mode.startswith("search only"):
                log("Using Search API pagination only.")
                records, used_mode = export_search(cfg, log, progress, self.stop_event)

            else:
                log("Trying Browse API first.")
                try:
                    records, used_mode = export_browse(cfg, log, progress, self.stop_event)
                except AlgoliaHTTPError as e:
                    if e.status in (401, 403):
                        log(f"Browse unavailable with this key ({e}). Falling back to Search API pagination.")
                        records, used_mode = export_search(cfg, log, progress, self.stop_event)
                    else:
                        raise

            if self.stop_event.is_set():
                log("Stopped by user. Saving partial export.")

            save_records(records, cfg.output_path, cfg.output_format)
            self.messages.put(("done", (len(records), used_mode, str(cfg.output_path))))

        except Exception as e:
            tb = traceback.format_exc()
            self.messages.put(("error", f"{e}\n\n{tb}"))

    def _poll_messages(self):
        try:
            while True:
                kind, payload = self.messages.get_nowait()

                if kind == "log":
                    self._log(str(payload))

                elif kind == "progress":
                    count, total, status = payload
                    self.var_status.set(f"{status} | {count} records")
                    if total and total > 0:
                        pct = max(0, min(100, (count / total) * 100))
                        self.progress.configure(mode="determinate", maximum=100, value=pct)
                    else:
                        self.progress.configure(mode="indeterminate")
                        self.progress.start(10)
                    self._log(f"{status}; total saved in memory: {count}")

                elif kind == "done":
                    count, used_mode, path = payload
                    self.progress.stop()
                    self.progress.configure(mode="determinate", value=100)
                    self.var_status.set(f"Done: {count} records")
                    self._log(f"Done. Exported {count} records using {used_mode}.")
                    self._log(f"Saved to: {path}")
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    messagebox.showinfo(APP_TITLE, f"Export complete.\n\nRecords: {count}\nMode: {used_mode}\nFile: {path}")

                elif kind == "error":
                    self.progress.stop()
                    self.var_status.set("Error")
                    self._log("ERROR:")
                    self._log(str(payload))
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    messagebox.showerror(APP_TITLE, str(payload).split("\n\n")[0])

        except queue.Empty:
            pass

        self.after(100, self._poll_messages)


if __name__ == "__main__":
    app = AlgoliaExporterGUI()
    app.mainloop()
