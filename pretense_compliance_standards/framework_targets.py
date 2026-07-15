"""
framework_targets.py

Renders a framework's synthetic cases into **realistic codebase + database scan
targets**, so pointing pretense (or any DLP scanner) at one `frameworks/<FW>/`
folder scans real-looking files rather than a bare JSON manifest.

Per framework, `write_framework_targets` emits:

    database/dump.sql     CREATE TABLE + INSERT statements
    codebase/.env         KEY="value" credential-style lines
    codebase/config.yaml  a YAML list of records
    codebase/seed.json    a JSON seed array
    codebase/app.py       Python source with string-literal constants
    data/export.csv       a CSV export
    logs/service.log      log lines

Every case (all data kinds, obfuscation tiers 0-5 — the edge cases) is embedded
in each file, in that format's idiom and carefully escaped, so the values survive
embedding and stay **scannable**. Each file is banner-marked SYNTHETIC. Framework
names appear only in file/table/variable NAMES here, never as a scanned value.

`validate_scannable` re-scans each rendered file with the reference detector and
confirms it still recovers the framework's data kinds.
"""

from __future__ import annotations

import csv
import io
import json

from . import BANNER
from .detector import detect

# ruff: noqa: S608 — this module generates synthetic SQL *dump files* as scan
# targets (never executed against a database); the INSERT string construction is
# intentional and single quotes are escaped. Scoped to this file so the
# SQL-injection guard stays active everywhere else.

# Fixed timestamp keeps generation deterministic (no wall-clock in output).
_TS = "2026-01-01T00:00:00Z"


def _sql_escape(value: str) -> str:
    return value.replace("'", "''")


def _sql_dump(cases: list[dict]) -> str:
    lines = [
        f"-- {BANNER}",
        "CREATE TABLE records (id TEXT, kind TEXT, payload TEXT);",
    ]
    for c in cases:
        # Synthetic SQL *dump file* (a scan target), never executed against a DB;
        # single quotes are escaped for valid literal syntax.
        lines.append(
            "INSERT INTO records (id, kind, payload) VALUES "
            f"('{_sql_escape(c['id'])}', '{_sql_escape(c['kind'])}', "
            f"'{_sql_escape(c['text'])}');"
        )
    return "\n".join(lines) + "\n"


def _env(fw: str, cases: list[dict]) -> str:
    lines = [f"# {BANNER}"]
    for i, c in enumerate(cases):
        key = f"{fw}_{c['kind'].upper()}_{i}"
        # JSON string == a valid double-quoted .env value; ensure_ascii=False keeps
        # homoglyph / zero-width edge cases literal (and scannable).
        lines.append(f"{key}={json.dumps(c['text'], ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def _yaml(cases: list[dict]) -> str:
    lines = [f"# {BANNER}", "records:"]
    for c in cases:
        lines.append(f"  - id: {c['id']}")
        lines.append(f"    kind: {c['kind']}")
        # A JSON string is a valid YAML (flow) scalar — dodges YAML special chars.
        lines.append(f"    value: {json.dumps(c['text'], ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def _json_seed(cases: list[dict]) -> str:
    payload = {
        "_notice": BANNER,
        "records": [
            {"id": c["id"], "kind": c["kind"], "text": c["text"]} for c in cases
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _python_app(cases: list[dict]) -> str:
    lines = [
        f"# {BANNER}",
        '"""Synthetic sample constants (fake data used as a scan target)."""',
        "",
        "SAMPLES = {",
    ]
    for i, c in enumerate(cases):
        # json.dumps yields a valid Python string literal too.
        key = f"{c['kind']}_{i}"
        lines.append(
            f"    {json.dumps(key)}: {json.dumps(c['text'], ensure_ascii=False)},"
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _csv_export(cases: list[dict]) -> str:
    buf = io.StringIO()
    buf.write(f"# {BANNER}\n")
    writer = csv.writer(buf)
    writer.writerow(["id", "kind", "payload"])
    for c in cases:
        writer.writerow([c["id"], c["kind"], c["text"]])
    return buf.getvalue()


def _log(cases: list[dict]) -> str:
    lines = [f"# {BANNER}"]
    for c in cases:
        lines.append(f"{_TS} INFO {c['id']} kind={c['kind']} :: {c['text']}")
    return "\n".join(lines) + "\n"


# rel-path -> renderer (renderers that need the framework name take it via _env).
def _render(fw: str, cases: list[dict]) -> dict[str, str]:
    return {
        "database/dump.sql": _sql_dump(cases),
        "codebase/.env": _env(fw, cases),
        "codebase/config.yaml": _yaml(cases),
        "codebase/seed.json": _json_seed(cases),
        "codebase/app.py": _python_app(cases),
        "data/export.csv": _csv_export(cases),
        "logs/service.log": _log(cases),
    }


# The scan-target files written per framework (for docs / tests).
TARGET_FILES = (
    "database/dump.sql",
    "codebase/.env",
    "codebase/config.yaml",
    "codebase/seed.json",
    "codebase/app.py",
    "data/export.csv",
    "logs/service.log",
)


def write_framework_targets(fw_dir, fw: str, cases: list[dict]) -> dict[str, str]:
    """Render + write the scan-target files for one framework. Returns
    {rel_path: content} for validation/tests."""
    files = _render(fw, cases)
    for rel, content in files.items():
        path = fw_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return files


def validate_scannable(cases: list[dict]) -> None:
    """Assert EVERY case's text stays detectable as its `kind` after embedding in
    each scan-target format — i.e. the escaping never hides the data. Checked
    per case (not per framework), so it covers every case in every format
    regardless of how cases are grouped into framework folders."""
    for c in cases:
        for rel, content in _render("SAMPLE", [c]).items():
            assert c["kind"] in detect(
                content, "hardened"
            ), f"{c['id']} ({c['kind']}) not scannable when embedded in {rel}"
