#!/usr/bin/env python3
"""
Plan stage (read-only) for BlueCat GitOps MVP (TXT only).

Input:
  out/normalized_requests.json  (from validate stage)

Output:
  out/plan.json
  out/plan_report.md

Goal:
  Compare desired intent (create/update/delete) with current BAM state and produce an action plan.
  This stage performs NO changes in BAM.

Design notes:
- Modular layout: config, API client, DNS adapter, planner, reports
- DNS adapter contains the only BAM-API-specific code for zone/record lookups
- Extend later by adding adapters/services for other object types (A, CNAME, IPAM, etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests


# -----------------------------
# Utilities
# -----------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# -----------------------------
# Config
# -----------------------------

@dataclass(frozen=True)
class BamAuthConfig:
    """
    Auth config for BAM session login.
    You said you have user/pass in CI vars and hit: /api/v2/sessions
    """
    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout_sec: int = 30


@dataclass(frozen=True)
class PlannerConfig:
    """
    Planner-level decisions.
    """
    # If a requested zone does not exist, safest is to FAIL (record ops cannot succeed)
    fail_on_missing_zone: bool = True

    # If any lookup is ambiguous (e.g., more than one match where we expect one),
    # safest is to FAIL rather than guessing.
    fail_on_ambiguous_match: bool = True


def read_config_from_env() -> Tuple[BamAuthConfig, PlannerConfig]:
    # Required
    base_url = os.environ.get("BAM_BASE_URL", "").strip().rstrip("/")
    user = os.environ.get("BAM_USER", "").strip()
    pw = os.environ.get("BAM_PASS", "").strip()

    if not base_url or not user or not pw:
        raise ValueError("Missing required env vars: BAM_BASE_URL, BAM_USER, BAM_PASS")

    auth = BamAuthConfig(
        base_url=base_url,
        username=user,
        password=pw,
        verify_ssl=False,
        timeout_sec=30,
    )

    planner_cfg = PlannerConfig(
        fail_on_missing_zone=os.environ.get("PLAN_FAIL_ON_MISSING_ZONE", "true").strip().lower() != "false",
        fail_on_ambiguous_match=os.environ.get("PLAN_FAIL_ON_AMBIGUOUS", "true").strip().lower() != "false",
    )
    return auth, planner_cfg


# -----------------------------
# BAM API Client (generic)
# -----------------------------

class BamApiClient:
    """
    Generic BAM API v2 client:
    - Handles session login: POST /api/v2/sessions
    - Stores auth token for subsequent calls
    - Provides a single request() method (GET/POST/etc.)
    """

    def __init__(self, cfg: BamAuthConfig) -> None:
        self.cfg = cfg
        self._token: Optional[str] = None
        self._session = requests.Session()

    def login(self) -> None:
        """
        Logs in and stores token.
        Endpoint provided by you: /api/v2/sessions
        """
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

        # Token field name can vary by deployment; handle common patterns.
        token = data.get("basicAuthenticationCredentials")
        if not token:
            raise RuntimeError(f"Login succeeded but token not found in response keys: {list(data.keys())}")
        self._token = str(token)

    def request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform an authenticated request to BAM.
        `path` must start with /api/v2/...
        """
        if not self._token:
            raise RuntimeError("Not logged in. Call login() first.")

        url = f"{self.cfg.base_url}{path}"
        headers = {
            "Authorization": f"Basic {self._token}",
            "Accept": "application/json",
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
        # Some endpoints may return empty body; normalize to {}
        if not resp.content:
            return {}
        return resp.json()


# -----------------------------
# DNS Adapter (BAM-specific lookups)
# -----------------------------

@dataclass(frozen=True)
class ZoneRef:
    view: str
    zone: str
    zone_id: str


@dataclass(frozen=True)
class TxtRecordRef:
    view: str
    zone: str
    name: str
    text: str
    record_id: str


class BlueCatDnsAdapter:
    """
    All BAM DNS endpoint knowledge should live here.

    For MVP Plan we need ONLY:
      - zone_exists(view, zone) -> ZoneRef | None
      - txt_exact_match(view, zone, name, text) -> List[TxtRecordRef]

    You will plug in the correct endpoints in these methods.
    Everything else (planning rules, reports, outputs) will work unchanged.
    """

    def __init__(self, api: BamApiClient) -> None:
        self.api = api

    def zone_exists(self, view: str, zone: str) -> Optional[ZoneRef]:
        """
        view comes from user as 'internal' but API shows view.name like 'Internal'
        """
        view_name = view[:1].upper() + view[1:] if view else ""

        # Build filter: absoluteName == fqdn AND view.name == Internal (optional)
        flt = f"absoluteName:eq('{zone}')"
        if view_name:
            flt = f"{flt} and view.name:eq('{view_name}')"

        data = self.api.request("GET", "/api/v2/zones", params={"filter": flt})

        items = data.get("data") or []
        if len(items) == 0:
            return None
        if len(items) > 1:
            raise RuntimeError(f"Ambiguous zone lookup for zone={zone} view={view_name} (count={len(items)})")
        
        return ZoneRef(view=view, zone=zone, zone_id=str(items[0]["id"]))

    def txt_exact_match(self, view: str, zone: str, name: str, text: str) -> List[TxtRecordRef]:
        zone_ref = self.zone_exists(view, zone)
        if zone_ref is None:
            return []
        
        data = self.api.request(
            "GET",
            f"/api/v2/zones/{zone_ref.zone_id}/resourceRecords",
            params={
                "filter": f"name:eq('{name}')"
            },
        )

        items = data.get("data") or []
        matches: List[TxtRecordRef] = []

        for item in items:
            # Ensure we only consider TXT
            if item in items:
                if item.get("recordType") != "TXT":
                    continue
                if item.get("text") != text:
                    continue

                matches.append(
                    TxtRecordRef(
                        view=view,
                        zone=zone,
                        name=name,
                        text=text,
                        record_id=str(item["id"]),
                    )
                )
        return matches


# -----------------------------
# Planning Domain
# -----------------------------

@dataclass
class PlanItem:
    request_key: str
    user_email: str
    labels: List[str]
    view: str
    type: str
    zone: str
    name: str
    action: str  # create|update|delete
    text: str
    new_text: Optional[str]

    planned: str  # create|update|delete|skip|fail
    reason: str
    details: Dict[str, Any]


class Planner:
    """
    Implements MVP planning rules (idempotent, no unnecessary change-control tasks).

    Rules (TXT MVP):
      create:
        - if exact (name+text) exists -> SKIP
        - else -> CREATE
      delete:
        - if exact exists -> DELETE
        - else -> SKIP
      update (replace old->new):
        - if old doesn't exist -> SKIP
        - if new already exists -> SKIP
        - else -> UPDATE (delete old + create new)

    Safety:
      - Zone must exist (FAIL if missing, per config)
      - If lookup returns >1 and config.fail_on_ambiguous_match -> FAIL
    """

    def __init__(self, dns: BlueCatDnsAdapter, cfg: PlannerConfig) -> None:
        self.dns = dns
        self.cfg = cfg

    def plan_txt(self, item: PlanItem) -> PlanItem:
        # 1) Zone must exist
        try:
            z = self.dns.zone_exists(item.view, item.zone)
        except NotImplementedError as nie:
            return self._fail(item, f"DNS adapter not implemented: {nie}")
        except Exception as e:
            return self._fail(item, f"Zone lookup error: {e}")

        if z is None:
            if self.cfg.fail_on_missing_zone:
                return self._fail(item, "Zone does not exist")
            return self._skip(item, "Zone does not exist (configured to skip)")

        # 2) Action-specific lookups
        if item.action == "create":
            return self._plan_create(item)
        if item.action == "delete":
            return self._plan_delete(item)
        if item.action == "update":
            return self._plan_update(item)
        return self._fail(item, f"Unsupported action: {item.action}")

    def _plan_create(self, item: PlanItem) -> PlanItem:
        matches = self._safe_txt_lookup(item.view, item.zone, item.name, item.text, item)
        if matches is None:
            return item  # already failed in _safe_txt_lookup

        if len(matches) == 0:
            return self._create(item, "Exact TXT does not exist; create is needed", {"match_count": 0})
        return self._skip(item, "Exact TXT already exists; skipping to avoid unnecessary task", {"match_count": len(matches)})

    def _plan_delete(self, item: PlanItem) -> PlanItem:
        matches = self._safe_txt_lookup(item.view, item.zone, item.name, item.text, item)
        if matches is None:
            return item

        if len(matches) == 0:
            return self._skip(item, "Exact TXT does not exist; skipping delete", {"match_count": 0})
        return self._delete(item, "Exact TXT exists; delete is needed", {"match_count": len(matches), "record_ids": [m.record_id for m in matches]})

    def _plan_update(self, item: PlanItem) -> PlanItem:
        if not item.new_text:
            return self._fail(item, "update requires new_text")

        # Lookup old
        old_matches = self._safe_txt_lookup(item.view, item.zone, item.name, item.text, item)
        if old_matches is None:
            return item

        if len(old_matches) == 0:
            return self._skip(item, "Old TXT value not found; skipping update", {"old_match_count": 0})

        # Lookup new
        new_matches = self._safe_txt_lookup(item.view, item.zone, item.name, item.new_text, item)
        if new_matches is None:
            return item

        if len(new_matches) > 0:
            return self._skip(item, "New TXT value already exists; skipping update", {"new_match_count": len(new_matches)})

        # Otherwise, plan an update (delete old + create new)
        return self._update(
            item,
            "Old exists and new does not; update is needed (delete old + create new)",
            {
                "old_record_ids": [m.record_id for m in old_matches],
                "old_match_count": len(old_matches),
                "new_match_count": len(new_matches),
            },
        )

    def _safe_txt_lookup(self, view: str, zone: str, name: str, text: str, item: PlanItem) -> Optional[List[TxtRecordRef]]:
        try:
            matches = self.dns.txt_exact_match(view=view, zone=zone, name=name, text=text)
        except NotImplementedError as nie:
            updated = self._fail(item, f"DNS adapter not implemented: {nie}")
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None
        except Exception as e:
            updated = self._fail(item, f"TXT lookup error: {e}")
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        if self.cfg.fail_on_ambiguous_match and len(matches) > 1:
            updated = self._fail(item, "Ambiguous match: more than one exact TXT record found", {"match_count": len(matches)})
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        return matches

    # Outcome helpers
    def _fail(self, item: PlanItem, reason: str, details: Optional[Dict[str, Any]] = None) -> PlanItem:
        item.planned = "fail"
        item.reason = reason
        item.details = details or {}
        return item

    def _skip(self, item: PlanItem, reason: str, details: Optional[Dict[str, Any]] = None) -> PlanItem:
        item.planned = "skip"
        item.reason = reason
        item.details = details or {}
        return item

    def _create(self, item: PlanItem, reason: str, details: Dict[str, Any]) -> PlanItem:
        item.planned = "create"
        item.reason = reason
        item.details = details
        return item

    def _delete(self, item: PlanItem, reason: str, details: Dict[str, Any]) -> PlanItem:
        item.planned = "delete"
        item.reason = reason
        item.details = details
        return item

    def _update(self, item: PlanItem, reason: str, details: Dict[str, Any]) -> PlanItem:
        item.planned = "update"
        item.reason = reason
        item.details = details
        return item


# -----------------------------
# Parsing normalized_requests.json -> PlanItems
# -----------------------------

def build_plan_items(normalized: Dict[str, Any]) -> List[PlanItem]:
    items: List[PlanItem] = []

    for req in normalized.get("requests", []):
        request_key = req.get("request_key", "")
        user_email = req.get("user_email", "")
        for act in req.get("actions", []):
            action = act.get("action")
            view = act.get("view", "internal")
            labels = act.get("labels", []) or []

            for rec in act.get("records", []):
                if rec.get("type") != "txt":
                    # Future-proof: ignore non-txt for now
                    continue

                items.append(
                    PlanItem(
                        request_key=request_key,
                        user_email=user_email,
                        labels=labels,
                        view=view,
                        type="txt",
                        zone=rec.get("zone", ""),
                        name=rec.get("name", ""),
                        action=action,
                        text=rec.get("text", ""),
                        new_text=rec.get("new_text"),
                        planned="fail",   # default, planner will set final state
                        reason="not planned yet",
                        details={},
                    )
                )

    return items


# -----------------------------
# Reporting
# -----------------------------

def summarize(plan_items: List[PlanItem]) -> Dict[str, int]:
    counts: Dict[str, int] = {"create": 0, "update": 0, "delete": 0, "skip": 0, "fail": 0}
    for it in plan_items:
        counts[it.planned] = counts.get(it.planned, 0) + 1
    return counts


def render_plan_report(plan_items: List[PlanItem], counts: Dict[str, int]) -> str:
    lines: List[str] = []
    lines.append("# Plan Report\n")
    lines.append(f"- Generated: `{now_iso()}`")
    lines.append(f"- Total items: `{len(plan_items)}`")
    lines.append(f"- Create: `{counts.get('create', 0)}`")
    lines.append(f"- Update: `{counts.get('update', 0)}`")
    lines.append(f"- Delete: `{counts.get('delete', 0)}`")
    lines.append(f"- Skip: `{counts.get('skip', 0)}`")
    lines.append(f"- Fail: `{counts.get('fail', 0)}`\n")

    # Show only failures + a short per-item summary (keeps the report readable)
    failures = [it for it in plan_items if it.planned == "fail"]
    if failures:
        lines.append("## Failures\n")
        for it in failures:
            lines.append(
                f"- **FAIL** `{it.request_key}` :: `{it.view}` `{it.zone}` `{it.name}` `{it.type}` "
                f"action=`{it.action}` text=`{it.text}` new_text=`{it.new_text}` â€” {it.reason}"
            )
        lines.append("")

    lines.append("## Items\n")
    for it in plan_items:
        lines.append(
            f"- `{it.planned.upper()}` `{it.view}` `{it.zone}` `{it.name}` `{it.type}` "
            f"action=`{it.action}` text=`{it.text}` new_text=`{it.new_text}` â€” {it.reason}"
        )

    lines.append("")
    return "\n".join(lines)


# -----------------------------
# Main
# -----------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="input_path", required=True, help="Input normalized_requests.json")
    parser.add_argument("--out", dest="out_dir", default="out", help="Output directory (default: out)")
    args = parser.parse_args()

    in_path = Path(args.input_path)
    out_dir = Path(args.out_dir)

    if not in_path.exists():
        print(f"ERROR: input file does not exist: {in_path}", file=sys.stderr)
        return 2

    # Load normalized contract
    normalized = load_json(in_path)
    plan_items = build_plan_items(normalized)

    # Auth + client
    try:
        auth_cfg, planner_cfg = read_config_from_env()
    except Exception as e:
        # If env not set, fail fast; this stage depends on BAM access.
        plan_payload = {
            "generated_at": now_iso(),
            "error": f"Config error: {e}",
            "counts": {"fail": len(plan_items)},
            "items": [asdict(it) for it in plan_items],
        }
        write_json(out_dir / "plan.json", plan_payload)
        write_text(out_dir / "plan_report.md", f"# Plan Report\n\nâŒ Config error: {e}\n")
        return 2

    api = BamApiClient(auth_cfg)
    try:
        api.login()
        # DEBUGGING BLOCK
        # dns = BlueCatDnsAdapter(api)
        # z = dns.zone_exists("internal", "mgictest.com")
        # print("ZONE LOOKUP RESULT:", z)
        # return 0
        # DEBUGGING BLOCK
    except Exception as e:
        write_text(out_dir / "plan_report.md", f"# Plan Report\n\nâŒ BAM login failed: {e}\n")
        write_json(out_dir / "plan.json", {"generated_at": now_iso(), "error": f"login failed: {e}", "items": []})
        return 2

    dns = BlueCatDnsAdapter(api)
    planner = Planner(dns, planner_cfg)

    # Plan each TXT item
    planned: List[PlanItem] = []
    for it in plan_items:
        if it.type != "txt":
            it.planned = "skip"
            it.reason = "Non-TXT type not supported in MVP"
            it.details = {}
            planned.append(it)
            continue
        planned.append(planner.plan_txt(it))

    counts = summarize(planned)

    # Write outputs
    plan_payload = {
        "generated_at": now_iso(),
        "counts": counts,
        "items": [asdict(it) for it in planned],
    }
    write_json(out_dir / "plan.json", plan_payload)
    write_text(out_dir / "plan_report.md", render_plan_report(planned, counts))

    # Fail the job if any plan item is fail (keeps pipeline honest)
    return 2 if counts.get("fail", 0) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
