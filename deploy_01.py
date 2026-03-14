#!/usr/bin/env python3
"""
Deploy stage (write) for BlueCat GitOps MVP (TXT only).

Input:
  out/plan.json   (from plan stage)

Output:
  out/deploy_report.md

Behavior (MVP):
- Executes only items planned as: create/update/delete
- Skips items planned as: skip
- Fails the job if any item is planned as: fail OR if any execution call fails

BlueCat endpoints (provided by you):
- Create RR under zone: POST   /api/v2/zones/<zone_id>/resourceRecords
- Delete RR by id:      DELETE /api/v2/resourceRecords/<rr_id>
- Update RR by id:      PUT    /api/v2/resourceRecords/<rr_id>

Important:
- We are using a limited BAM account so BAM will create Change Control tasks.
- We do NOT verify task creation in MVP (no post-checks).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# -----------------------------
# Utilities
# -----------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# -----------------------------
# Config
# -----------------------------

@dataclass(frozen=True)
class BamAuthConfig:
    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout_sec: int = 30


def read_auth_from_env() -> BamAuthConfig:
    base_url = os.environ.get("BAM_BASE_URL", "").strip().rstrip("/")
    user = os.environ.get("BAM_USER", "").strip()
    pw = os.environ.get("BAM_PASS", "").strip()

    if not base_url or not user or not pw:
        raise ValueError("Missing required env vars: BAM_BASE_URL, BAM_USER, BAM_PASS")

    # For MVP you're using self-signed / internal certs; keep verify_ssl False
    return BamAuthConfig(base_url=base_url, username=user, password=pw, verify_ssl=False, timeout_sec=30)


# -----------------------------
# BAM API Client
# -----------------------------

class BamApiClient:
    """
    Minimal BAM v2 client:
    - login(): POST /api/v2/sessions -> returns basicAuthenticationCredentials (token)
    - request(): authenticated calls with Basic <token>
    """

    def __init__(self, cfg: BamAuthConfig) -> None:
        self.cfg = cfg
        self._token: Optional[str] = None
        self._session = requests.Session()

    def login(self) -> None:
        url = f"{self.cfg.base_url}/api/v2/sessions"
        payload = {"username": self.cfg.username, "password": self.cfg.password}

        resp = self._session.post(
            url,
            json=payload,
            timeout=self.cfg.timeout_sec,
            verify=self.cfg.verify_ssl,
        )
        resp.raise_for_status()
        data = resp.json()

        token = data.get("basicAuthenticationCredentials")
        if not token:
            raise RuntimeError(f"Login succeeded but token not found in response keys: {list(data.keys())}")
        self._token = str(token)

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self._token:
            raise RuntimeError("Not logged in. Call login() first.")

        url = f"{self.cfg.base_url}{path}"
        headers = {
            "Authorization": f"Basic {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        resp = self._session.request(
            method=method.upper(),
            url=url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=self.cfg.timeout_sec,
            verify=self.cfg.verify_ssl,
        )

        # DELETE can legitimately return empty body (as you observed)
        resp.raise_for_status()
        if not resp.content:
            return {}
        return resp.json()


# -----------------------------
# Deploy executor (TXT only)
# -----------------------------

def _as_str(v: Any) -> str:
    return "" if v is None else str(v)


def deploy_txt(api: BamApiClient, item: Dict[str, Any]) -> Tuple[str, str]:
    """
    Returns: (status, message)
      status: OK | FAIL | SKIP
    """
    planned = _as_str(item.get("planned")).lower()
    action = _as_str(item.get("action")).lower()
    zone_id = _as_str(item.get("zone_id")).strip()
    rr_id = _as_str((item.get("details") or {}).get("rr_id")).strip()

    view = _as_str(item.get("view"))
    zone = _as_str(item.get("zone"))
    name = _as_str(item.get("name"))
    text = _as_str(item.get("text"))
    new_text = item.get("new_text")

    # Only execute for create/update/delete
    if planned in {"skip"}:
        return "SKIP", _as_str(item.get("reason")) or "planned=skip"
    if planned == "fail":
        return "FAIL", _as_str(item.get("reason")) or "planned=fail"
    if planned not in {"create", "update", "delete"}:
        return "FAIL", f"Unsupported planned value: {planned}"

    # MVP safety checks: plan must provide IDs
    if not zone_id:
        return "FAIL", "Missing zone_id in plan item (plan stage must resolve it)"

    # Execute
    if planned == "create":
        # POST /api/v2/zones/<zone_id>/resourceRecords
        body = {
            "type": "TXTRecord",     # BAM expects object type name (not 'txt')
            "name": name,
            "text": text,
        }
        api.request("POST", f"/api/v2/zones/{zone_id}/resourceRecords", json_body=body)
        return "OK", f"Created TXT (Change Control requested) view={view} zone={zone} name={name} text={text}"

    if planned == "delete":
        if not rr_id:
            return "FAIL", "Missing details.rr_id for delete"
        # DELETE /api/v2/resourceRecords/<rr_id>
        api.request("DELETE", f"/api/v2/resourceRecords/{rr_id}")
        return "OK", f"Deleted TXT (Change Control requested) id={rr_id} view={view} zone={zone} name={name} text={text}"

    # planned == "update"
    if not rr_id:
        return "FAIL", "Missing details.rr_id for update"
    if not new_text:
        return "FAIL", "Missing new_text for update"

    body = {
        "type": "TXTRecord",
        "name": name,
        "text": str(new_text),
    }
    # PUT /api/v2/resourceRecords/<rr_id>
    api.request("PUT", f"/api/v2/resourceRecords/{rr_id}", json_body=body)
    return "OK", f"Updated TXT (Change Control requested) id={rr_id} view={view} zone={zone} name={name} text={text} -> {new_text}"


# -----------------------------
# Reporting
# -----------------------------

def render_deploy_report(results: List[Dict[str, Any]]) -> str:
    ok = sum(1 for r in results if r["status"] == "OK")
    skip = sum(1 for r in results if r["status"] == "SKIP")
    fail = sum(1 for r in results if r["status"] == "FAIL")

    lines: List[str] = []
    lines.append("# Deploy Report\n")
    lines.append(f"- Generated: `{now_iso()}`")
    lines.append(f"- OK: `{ok}`")
    lines.append(f"- SKIP: `{skip}`")
    lines.append(f"- FAIL: `{fail}`\n")

    if fail:
        lines.append("## Failures\n")
        for r in results:
            if r["status"] != "FAIL":
                continue
            lines.append(f"- **FAIL** `{r['request_key']}` :: {r['summary']} — {r['message']}")
        lines.append("")

    lines.append("## Items\n")
    for r in results:
        lines.append(f"- `{r['status']}` `{r['request_key']}` :: {r['summary']} — {r['message']}")
    lines.append("")
    return "\n".join(lines)


# -----------------------------
# Main
# -----------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="input_path", required=True, help="Input plan.json")
    parser.add_argument("--out", dest="out_dir", default="out", help="Output directory (default: out)")
    args = parser.parse_args()

    in_path = Path(args.input_path)
    out_dir = Path(args.out_dir)

    if not in_path.exists():
        print(f"ERROR: input file does not exist: {in_path}", file=sys.stderr)
        return 2

    plan = load_json(in_path)
    items = plan.get("items") or []

    # If plan already contains failures, fail deploy immediately (keeps workflow strict)
    if any(str(it.get("planned", "")).lower() == "fail" for it in items):
        write_text(out_dir / "deploy_report.md", "# Deploy Report\n\n❌ plan.json contains FAIL items; fix plan stage first.\n")
        return 2

    # Auth
    try:
        auth = read_auth_from_env()
    except Exception as e:
        write_text(out_dir / "deploy_report.md", f"# Deploy Report\n\n❌ Config error: {e}\n")
        return 2

    api = BamApiClient(auth)
    try:
        api.login()
    except Exception as e:
        write_text(out_dir / "deploy_report.md", f"# Deploy Report\n\n❌ BAM login failed: {e}\n")
        return 2

    results: List[Dict[str, Any]] = []
    for it in items:
        summary = (
            f"{it.get('view')} {it.get('zone')} {it.get('name')} {it.get('type')} "
            f"action={it.get('action')} planned={it.get('planned')}"
        )
        status, msg = deploy_txt(api, it) if str(it.get("type")).lower() == "txt" else ("SKIP", "Non-TXT not supported in MVP")

        results.append(
            {
                "request_key": it.get("request_key", ""),
                "status": status,
                "summary": summary,
                "message": msg,
            }
        )

    report = render_deploy_report(results)
    write_text(out_dir / "deploy_report.md", report)

    # Fail pipeline if any FAIL
    return 2 if any(r["status"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
