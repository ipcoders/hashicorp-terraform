#!/usr/bin/env python3
"""
------------------------------------------------------------------------------
Script: deploy_requests.py
------------------------------------------------------------------------------

Purpose
------------------------------------------------------------------------------
This script performs the Deploy stage for the BlueCat GitOps MVP.

It reads the action plan produced by the Plan stage and executes the approved
TXT record operations against BlueCat BAM.

This is the first stage in the pipeline that performs write operations.

Its job is to take the planner's decisions and carry them out in BAM for
items that were explicitly planned as:

    - create
    - update
    - delete

This stage does NOT perform planning logic again. It trusts the plan artifact
and executes only what the plan stage determined to be necessary and safe.


------------------------------------------------------------------------------
Input
------------------------------------------------------------------------------
The script expects a planning artifact as input:

    out/plan.json

This file is produced by plan_requests.py and contains a list of planned TXT
record actions.

The current contract consumed by this script is:

    {
      "generated_at": "...",
      "counts": {
        "create": <n>,
        "update": <n>,
        "delete": <n>,
        "skip": <n>,
        "fail": <n>
      },
      "items": [
        {
          "request_key": "...",
          "user_email": "...",
          "labels": [...],
          "view": "...",
          "type": "txt",
          "zone": "...",
          "name": "...",
          "action": "create|update|delete",
          "text": "...",
          "new_text": "...",
          "planned": "create|update|delete|skip|fail",
          "reason": "...",
          "details": {...},
          "zone_id": "..."
        }
      ]
    }

Only TXT records are executed in the current MVP.


------------------------------------------------------------------------------
Output
------------------------------------------------------------------------------
The script produces one artifact:

1) out/deploy_report.md

Human-readable deployment report containing:

    - generation timestamp
    - execution counts
    - failure details
    - per-item execution results


------------------------------------------------------------------------------
External Dependencies
------------------------------------------------------------------------------
This stage requires access to BlueCat BAM through API v2.

It authenticates using:

    POST /api/v2/sessions

and then executes write operations using the following endpoints:

    Create record under zone:
        POST /api/v2/zones/<zone_id>/resourceRecords

    Delete record by record ID:
        DELETE /api/v2/resourceRecords/<rr_id>

    Update record by record ID:
        PUT /api/v2/resourceRecords/<rr_id>

Required environment variables:

    BAM_BASE_URL
    BAM_USER
    BAM_PASS

For MVP, SSL verification is disabled because the environment uses self-signed
or internal certificates.


------------------------------------------------------------------------------
High-Level Flow
------------------------------------------------------------------------------
The script performs the following steps:

1. Load plan.json
2. Verify the file exists
3. Fail immediately if any item in the plan is already marked as planned=fail
4. Read BlueCat authentication settings from environment variables
5. Log in to BlueCat BAM
6. For each plan item:
       - execute CREATE if planned=create
       - execute UPDATE if planned=update
       - execute DELETE if planned=delete
       - record SKIP if planned=skip
       - record FAIL if the item is invalid or execution fails
7. Write deploy_report.md
8. Return non-zero exit code if any item fails


------------------------------------------------------------------------------
Execution Model (TXT-only MVP)
------------------------------------------------------------------------------
This stage executes only TXT record operations.

It does not perform fresh BAM lookups to re-evaluate state. Instead, it relies
on the planning artifact generated earlier in the pipeline.

Execution is driven by the value of each item's `planned` field:

    create -> perform API create call
    update -> perform API update call
    delete -> perform API delete call
    skip   -> do not execute anything
    fail   -> treat as deployment failure

This strict separation keeps responsibilities clear:

    validate stage -> structure and normalization
    plan stage     -> state-aware decision making
    deploy stage   -> execution only


------------------------------------------------------------------------------
Supported Actions
------------------------------------------------------------------------------

CREATE
    Behavior:
        - requires zone_id from the plan stage
        - sends POST request to create a TXT record under the resolved zone

    API payload:
        {
          "type": "TXTRecord",
          "name": "<record_name>",
          "text": "<txt_value>"
        }


DELETE
    Behavior:
        - requires details.rr_id from the plan stage
        - sends DELETE request for the specific TXT record ID


UPDATE
    Behavior:
        - requires details.rr_id from the plan stage
        - requires new_text
        - sends PUT request to update the existing TXT record value

    API payload:
        {
          "type": "TXTRecord",
          "name": "<record_name>",
          "text": "<new_txt_value>"
        }


------------------------------------------------------------------------------
Safety Rules
------------------------------------------------------------------------------
This stage is intentionally strict.

1) plan.json must not contain any planned=fail items
   If the plan artifact already includes failures, deployment stops
   immediately.

   Reason:
   The plan stage is the source of truth for whether execution is safe.

2) zone_id is required for planned=create
   If zone_id is missing, deployment fails for that item.

   Reason:
   Create operations need a parent zone container.

3) details.rr_id is required for planned=delete and planned=update
   If rr_id is missing, deployment fails for that item.

   Reason:
   Delete and update operations must target a specific existing record.

4) new_text is required for planned=update
   If new_text is missing, deployment fails for that item.

5) unsupported planned values result in FAIL
   Any unexpected value outside:

        create | update | delete | skip | fail

   is treated as an execution error.

6) non-TXT records are skipped
   Non-TXT records are not supported in the current MVP.


------------------------------------------------------------------------------
Execution Outcomes
------------------------------------------------------------------------------
Each processed plan item receives one final deployment result:

OK
    The requested BAM write operation completed successfully.

    Examples:
        - TXT record created
        - TXT record updated
        - TXT record deleted

SKIP
    No BAM API call was executed for the item.

    Examples:
        - the plan item was marked planned=skip
        - the item type is not TXT in the current MVP

FAIL
    The deploy stage could not safely execute the item.

    Examples:
        - plan.json already contained planned=fail items
        - required fields such as zone_id or rr_id were missing
        - BAM login failed
        - the BAM API call returned an error
        - the planned value was unsupported


Pipeline behavior:

    OK    -> pipeline continues
    SKIP  -> pipeline continues
    FAIL  -> pipeline exits with error (exit code 2)


------------------------------------------------------------------------------
Change Control Behavior
------------------------------------------------------------------------------
The BAM account used by this stage is limited and is expected to create
Change Control tasks automatically when write operations are submitted.

Current MVP behavior:

    - write calls are executed
    - Change Control task creation is assumed
    - no post-check is performed to verify task creation

This means the script confirms that the API request succeeded, but it does
not yet verify downstream workflow objects such as generated tasks.


------------------------------------------------------------------------------
Report Design
------------------------------------------------------------------------------
deploy_report.md is designed for human review.

It contains:

    - total counts by result (OK / SKIP / FAIL)
    - a failures section for fast troubleshooting
    - a full item-by-item execution summary

The report is intended to make CI results easy to review without requiring
users to inspect raw logs.


------------------------------------------------------------------------------
Exit Codes
------------------------------------------------------------------------------

Exit 0
    Deployment completed and no item failed

Exit 2
    One or more of the following occurred:
        - input file missing
        - configuration error
        - BAM login failure
        - plan.json contained planned=fail items
        - at least one deployment item failed


------------------------------------------------------------------------------
Design Philosophy
------------------------------------------------------------------------------
This stage is deliberately narrow in responsibility.

It does NOT:

    - validate YAML structure
    - normalize request content
    - decide whether a change is needed
    - re-plan against live BAM state
    - verify Change Control task creation after submission

Those responsibilities belong to earlier or future stages.

The deploy stage exists to execute the approved plan as-is, fail loudly when
required execution data is missing, and keep the pipeline behavior predictable
and auditable.
------------------------------------------------------------------------------
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

    # Action-specific safety checks
    if planned == "create":
        if not zone_id:
            return "FAIL", "Missing zone_id in plan item for create"

    elif planned == "delete":
        if not rr_id:
            return "FAIL", "Missing details.rr_id for delete"

    elif planned == "update":
        if not rr_id:
            return "FAIL", "Missing details.rr_id for update"
        if not new_text:
            return "FAIL", "Missing new_text for update"

    # Execute
    if planned == "create":
        # POST /api/v2/zones/<zone_id>/resourceRecords
        body = {
            "type": "TXTRecord",
            "name": name,
            "text": text,
        }
        api.request("POST", f"/api/v2/zones/{zone_id}/resourceRecords", json_body=body)
        return "OK", f"Created TXT (Change Control requested) view={view} zone={zone} name={name} text={text}"

    if planned == "delete":
        # DELETE /api/v2/resourceRecords/<rr_id>
        api.request("DELETE", f"/api/v2/resourceRecords/{rr_id}")
        return "OK", f"Deleted TXT (Change Control requested) id={rr_id} view={view} zone={zone} name={name} text={text}"

    # planned == "update"
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
  
