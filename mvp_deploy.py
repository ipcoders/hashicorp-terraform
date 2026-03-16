#!/usr/bin/env python3
"""
Deploy stage (write) for BlueCat GitOps MVP.

Supported objects:
- records:
  - TXT
- ipam:
  - IPv4 network (create only)

Input:
  out/plan.json

Output:
  out/deploy_report.md
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

    return BamAuthConfig(base_url=base_url, username=user, password=pw, verify_ssl=False, timeout_sec=30)


# -----------------------------
# BAM API Client
# -----------------------------

class BamApiClient:
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

        resp.raise_for_status()
        if not resp.content:
            return {}
        return resp.json()


# -----------------------------
# Deploy executors
# -----------------------------

def _as_str(v: Any) -> str:
    return "" if v is None else str(v)


def deploy_txt(api: BamApiClient, item: Dict[str, Any]) -> Tuple[str, str]:
    planned = _as_str(item.get("planned")).lower()
    zone_id = _as_str(item.get("zone_id")).strip()
    rr_id = _as_str((item.get("details") or {}).get("rr_id")).strip()

    view = _as_str(item.get("view"))
    zone = _as_str(item.get("zone"))
    name = _as_str(item.get("name"))
    text = _as_str(item.get("text"))
    new_text = item.get("new_text")

    if planned == "skip":
        return "SKIP", _as_str(item.get("reason")) or "planned=skip"
    if planned == "fail":
        return "FAIL", _as_str(item.get("reason")) or "planned=fail"
    if planned not in {"create", "update", "delete"}:
        return "FAIL", f"Unsupported planned value: {planned}"

    if planned == "create":
        if not zone_id:
            return "FAIL", "Missing zone_id in plan item for create"

        body = {
            "type": "TXTRecord",
            "name": name,
            "text": text,
        }
        api.request("POST", f"/api/v2/zones/{zone_id}/resourceRecords", json_body=body)
        return "OK", f"Created TXT view={view} zone={zone} name={name} text={text}"

    if planned == "delete":
        if not rr_id:
            return "FAIL", "Missing details.rr_id for delete"

        api.request("DELETE", f"/api/v2/resourceRecords/{rr_id}")
        return "OK", f"Deleted TXT id={rr_id} view={view} zone={zone} name={name} text={text}"

    if not rr_id:
        return "FAIL", "Missing details.rr_id for update"
    if not new_text:
        return "FAIL", "Missing new_text for update"

    body = {
        "type": "TXTRecord",
        "name": name,
        "text": str(new_text),
    }
    api.request("PUT", f"/api/v2/resourceRecords/{rr_id}", json_body=body)
    return "OK", f"Updated TXT id={rr_id} view={view} zone={zone} name={name} text={text} -> {new_text}"


def deploy_ipv4_network(api: BamApiClient, item: Dict[str, Any]) -> Tuple[str, str]:
    planned = _as_str(item.get("planned")).lower()
    parent_block_id = _as_str(item.get("parent_block_id")).strip()
    requested_range = _as_str(item.get("range")).strip()
    configuration = _as_str(item.get("configuration")).strip()

    if planned == "skip":
        return "SKIP", _as_str(item.get("reason")) or "planned=skip"
    if planned == "fail":
        return "FAIL", _as_str(item.get("reason")) or "planned=fail"
    if planned != "create":
        return "FAIL", f"ipv4_network supports only planned=create in MVP (got: {planned})"

    if not parent_block_id:
        return "FAIL", "Missing parent_block_id in plan item for ipv4_network create"
    if not requested_range:
        return "FAIL", "Missing range in plan item for ipv4_network create"

    body = {
        "type": "IPv4Network",
        "range": requested_range,
    }
    api.request("POST", f"/api/v2/blocks/{parent_block_id}/networks", json_body=body)
    return "OK", f"Created IPv4 network configuration={configuration} parent_block_id={parent_block_id} range={requested_range}"


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
            lines.append(f"- **FAIL** `{r['request_key']}` :: {r['summary']} - {r['message']}")
        lines.append("")

    lines.append("## Items\n")
    for r in results:
        lines.append(f"- `{r['status']}` `{r['request_key']}` :: {r['summary']} - {r['message']}")
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

    if any(str(it.get("planned", "")).lower() == "fail" for it in items):
        write_text(out_dir / "deploy_report.md", "# Deploy Report\n\nplan.json contains FAIL items; fix plan stage first.\n")
        return 2

    try:
        auth = read_auth_from_env()
    except Exception as e:
        write_text(out_dir / "deploy_report.md", f"# Deploy Report\n\nConfig error: {e}\n")
        return 2

    api = BamApiClient(auth)
    try:
        api.login()
    except Exception as e:
        write_text(out_dir / "deploy_report.md", f"# Deploy Report\n\nBAM login failed: {e}\n")
        return 2

    results: List[Dict[str, Any]] = []
    for it in items:
        rr_type = str(it.get("type", "")).lower()

        if rr_type == "txt":
            summary = (
                f"{it.get('view')} {it.get('zone')} {it.get('name')} {it.get('type')} "
                f"action={it.get('action')} planned={it.get('planned')}"
            )
            status, msg = deploy_txt(api, it)

        elif rr_type == "ipv4_network":
            summary = (
                f"configuration={it.get('configuration')} parent_block={it.get('parent_block')} "
                f"range={it.get('range')} {it.get('type')} action={it.get('action')} planned={it.get('planned')}"
            )
            status, msg = deploy_ipv4_network(api, it)

        else:
            summary = f"type={it.get('type')} action={it.get('action')} planned={it.get('planned')}"
            status, msg = "SKIP", "Unsupported type in MVP"

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

    return 2 if any(r["status"] == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
