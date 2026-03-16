#!/usr/bin/env python3
"""
Plan stage (read-only) for BlueCat GitOps MVP.

Supported objects:
- records:
  - TXT
- ipam:
  - IPv4 network (create only)

Input:
  out/normalized_requests.json

Output:
  out/plan.json
  out/plan_report.md
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

CONFIGURATION_IDS: Dict[str, str] = {
    "dre": "291883",
    "mgic int": "100887",
}


def normalize_configuration_name(name: str) -> str:
    return " ".join((name or "").strip().lower().replace("_", " ").split())


def resolve_configuration_id(name: str) -> Optional[str]:
    return CONFIGURATION_IDS.get(normalize_configuration_name(name))


@dataclass(frozen=True)
class BamAuthConfig:
    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout_sec: int = 30


@dataclass(frozen=True)
class PlannerConfig:
    fail_on_missing_zone: bool = True
    fail_on_ambiguous_match: bool = True


def read_config_from_env() -> Tuple[BamAuthConfig, PlannerConfig]:
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
# DNS / IPAM Adapter
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


@dataclass(frozen=True)
class BlockRef:
    configuration_id: str
    configuration_name: str
    range: str
    block_id: str


@dataclass(frozen=True)
class NetworkRef:
    configuration_id: str
    configuration_name: str
    range: str
    network_id: str


class BlueCatAdapter:
    def __init__(self, api: BamApiClient) -> None:
        self.api = api

    # ---- DNS / TXT ----

    def zone_exists(self, view: str, zone: str) -> Optional[ZoneRef]:
        view_name = view[:1].upper() + view[1:] if view else ""

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
            params={"filter": f"name:eq('{name}')"},
        )

        items = data.get("data") or []
        matches: List[TxtRecordRef] = []

        for item in items:
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

    # ---- IPAM / Blocks / Networks ----

    def ipv4_block_exact_match(self, configuration_id: str, cidr: str) -> List[BlockRef]:
        flt = f"type:eq('IPv4Block') and range:eq('{cidr}')"
        data = self.api.request("GET", "/api/v2/blocks", params={"filter": flt})

        items = data.get("data") or []
        matches: List[BlockRef] = []
        for item in items:
            cfg = item.get("configuration") or {}
            if str(cfg.get("id", "")) != str(configuration_id):
                continue
            matches.append(
                BlockRef(
                    configuration_id=str(cfg.get("id", "")),
                    configuration_name=str(cfg.get("name", "")),
                    range=str(item.get("range", "")),
                    block_id=str(item["id"]),
                )
            )
        return matches

    def ipv4_network_exact_match(self, configuration_id: str, cidr: str) -> List[NetworkRef]:
        flt = f"type:eq('IPv4Network') and range:eq('{cidr}')"
        data = self.api.request("GET", "/api/v2/networks", params={"filter": flt})

        items = data.get("data") or []
        matches: List[NetworkRef] = []
        for item in items:
            cfg = item.get("configuration") or {}
            if str(cfg.get("id", "")) != str(configuration_id):
                continue
            matches.append(
                NetworkRef(
                    configuration_id=str(cfg.get("id", "")),
                    configuration_name=str(cfg.get("name", "")),
                    range=str(item.get("range", "")),
                    network_id=str(item["id"]),
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
    action: str
    text: str
    planned: str
    reason: str
    details: Dict[str, Any]
    new_text: Optional[str]

    zone_id: Optional[str] = None
    configuration: str = ""
    configuration_id: Optional[str] = None
    parent_block: str = ""
    parent_block_id: Optional[str] = None
    range: str = ""


class Planner:
    def __init__(self, adapter: BlueCatAdapter, cfg: PlannerConfig) -> None:
        self.adapter = adapter
        self.cfg = cfg

    def plan_item(self, item: PlanItem) -> PlanItem:
        if item.type == "txt":
            return self.plan_txt(item)
        if item.type == "ipv4_network":
            return self.plan_ipv4_network(item)
        return self._fail(item, f"Unsupported type: {item.type}")

    # ---- TXT ----

    def plan_txt(self, item: PlanItem) -> PlanItem:
        try:
            z = self.adapter.zone_exists(item.view, item.zone)
        except Exception as e:
            return self._fail(item, f"Zone lookup error: {e}")

        if z is None:
            if self.cfg.fail_on_missing_zone:
                return self._fail(item, "Zone does not exist")
            return self._skip(item, "Zone does not exist (configured to skip)")

        item.zone_id = z.zone_id

        if item.action == "create":
            return self._plan_txt_create(item)
        if item.action == "delete":
            return self._plan_txt_delete(item)
        if item.action == "update":
            return self._plan_txt_update(item)
        return self._fail(item, f"Unsupported action: {item.action}")

    def _plan_txt_create(self, item: PlanItem) -> PlanItem:
        matches = self._safe_txt_lookup(item.view, item.zone, item.name, item.text, item)
        if matches is None:
            return item
        if len(matches) == 0:
            return self._create(item, "Exact TXT does not exist; create is needed", {"match_count": 0})
        return self._skip(item, "Exact TXT already exists; skipping to avoid unnecessary task", {"match_count": len(matches)})

    def _plan_txt_delete(self, item: PlanItem) -> PlanItem:
        matches = self._safe_txt_lookup(item.view, item.zone, item.name, item.text, item)
        if matches is None:
            return item
        if len(matches) == 0:
            return self._skip(item, "Exact TXT does not exist; skipping delete", {"match_count": 0})
        return self._delete(
            item,
            "Exact TXT exists; delete is needed",
            {"match_count": len(matches), "rr_id": matches[0].record_id, "record_ids": [m.record_id for m in matches]},
        )

    def _plan_txt_update(self, item: PlanItem) -> PlanItem:
        if not item.new_text:
            return self._fail(item, "update requires new_text")

        old_matches = self._safe_txt_lookup(item.view, item.zone, item.name, item.text, item)
        if old_matches is None:
            return item
        if len(old_matches) == 0:
            return self._skip(item, "Old TXT value not found; skipping update", {"old_match_count": 0})

        new_matches = self._safe_txt_lookup(item.view, item.zone, item.name, item.new_text, item)
        if new_matches is None:
            return item
        if len(new_matches) > 0:
            return self._skip(item, "New TXT value already exists; skipping update", {"new_match_count": len(new_matches)})

        return self._update(
            item,
            "Old exists and new does not; update is needed.",
            {
                "rr_id": old_matches[0].record_id,
                "old_record_ids": [m.record_id for m in old_matches],
                "old_match_count": len(old_matches),
                "new_match_count": len(new_matches),
            },
        )

    def _safe_txt_lookup(self, view: str, zone: str, name: str, text: str, item: PlanItem) -> Optional[List[TxtRecordRef]]:
        try:
            matches = self.adapter.txt_exact_match(view=view, zone=zone, name=name, text=text)
        except Exception as e:
            updated = self._fail(item, f"TXT lookup error: {e}")
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        if self.cfg.fail_on_ambiguous_match and len(matches) > 1:
            updated = self._fail(item, "Ambiguous match: more than one exact TXT record found", {"match_count": len(matches)})
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        return matches

    # ---- IPv4 Network (create only) ----

    def plan_ipv4_network(self, item: PlanItem) -> PlanItem:
        if item.action != "create":
            return self._fail(item, "ipv4_network currently supports only action=create")

        if not item.configuration_id:
            return self._fail(item, f"Unsupported configuration name: {item.configuration}")

        parent_blocks = self._safe_block_lookup(item.configuration_id, item.parent_block, item)
        if parent_blocks is None:
            return item
        if len(parent_blocks) == 0:
            return self._fail(item, "Parent block does not exist")
        if self.cfg.fail_on_ambiguous_match and len(parent_blocks) > 1:
            return self._fail(item, "Ambiguous match: more than one exact parent block found", {"match_count": len(parent_blocks)})

        item.parent_block_id = parent_blocks[0].block_id

        same_range_blocks = self._safe_block_lookup(item.configuration_id, item.range, item)
        if same_range_blocks is None:
            return item
        if len(same_range_blocks) > 0:
            return self._fail(item, "Requested range already exists as a block", {"match_count": len(same_range_blocks)})

        same_range_networks = self._safe_network_lookup(item.configuration_id, item.range, item)
        if same_range_networks is None:
            return item
        if len(same_range_networks) > 0:
            return self._skip(item, "Requested IPv4 network already exists; skipping create", {"match_count": len(same_range_networks)})

        return self._create(
            item,
            "Parent block exists and requested IPv4 network does not exist; create is needed",
            {
                "parent_block_id": item.parent_block_id,
                "configuration_id": item.configuration_id,
                "range": item.range,
            },
        )

    def _safe_block_lookup(self, configuration_id: str, cidr: str, item: PlanItem) -> Optional[List[BlockRef]]:
        try:
            matches = self.adapter.ipv4_block_exact_match(configuration_id=configuration_id, cidr=cidr)
        except Exception as e:
            updated = self._fail(item, f"IPv4 block lookup error: {e}")
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None
        return matches

    def _safe_network_lookup(self, configuration_id: str, cidr: str, item: PlanItem) -> Optional[List[NetworkRef]]:
        try:
            matches = self.adapter.ipv4_network_exact_match(configuration_id=configuration_id, cidr=cidr)
        except Exception as e:
            updated = self._fail(item, f"IPv4 network lookup error: {e}")
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        if self.cfg.fail_on_ambiguous_match and len(matches) > 1:
            updated = self._fail(item, "Ambiguous match: more than one exact IPv4 network found", {"match_count": len(matches)})
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        return matches

    # ---- Outcome helpers ----

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

            # Process ipam first
            for ipam_obj in (act.get("ipam") or []):
                if ipam_obj.get("type") != "ipv4_network":
                    continue

                configuration = str(ipam_obj.get("configuration", ""))
                items.append(
                    PlanItem(
                        request_key=request_key,
                        user_email=user_email,
                        labels=labels,
                        view="",
                        type="ipv4_network",
                        zone="",
                        name="",
                        action=action,
                        text="",
                        new_text=None,
                        planned="fail",
                        reason="not planned yet",
                        details={},
                        configuration=configuration,
                        configuration_id=resolve_configuration_id(configuration),
                        parent_block=str(ipam_obj.get("parent_block", "")),
                        range=str(ipam_obj.get("range", "")),
                    )
                )

            # Then records
            for rec in (act.get("records") or []):
                if rec.get("type") != "txt":
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
                        planned="fail",
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


def plan_item_summary(it: PlanItem) -> str:
    if it.type == "ipv4_network":
        return (
            f"`{it.type}` configuration=`{it.configuration}` parent_block=`{it.parent_block}` "
            f"range=`{it.range}` action=`{it.action}`"
        )

    return (
        f"`{it.view}` `{it.zone}` `{it.name}` `{it.type}` "
        f"action=`{it.action}` text=`{it.text}` new_text=`{it.new_text}`"
    )


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

    failures = [it for it in plan_items if it.planned == "fail"]
    if failures:
        lines.append("## Failures\n")
        for it in failures:
            lines.append(f"- **FAIL** `{it.request_key}` :: {plan_item_summary(it)} - {it.reason}")
        lines.append("")

    lines.append("## Items\n")
    for it in plan_items:
        lines.append(f"- `{it.planned.upper()}` {plan_item_summary(it)} - {it.reason}")

    lines.append("")
    return "\n".join(lines)


# -----------------------------
# Main
# -----------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", help="Request YAML files.")
    parser.add_argument("--in", dest="input_files", nargs="+", default=None, help="Request YAML files to validate.")
    parser.add_argument("--out", dest="out_dir", default="out", help="Output directory (default: out)")
    args = parser.parse_args()

    all_files: List[str] = []
    if args.files:
        all_files.extend(args.files)

    if args.input_files:
        all_files.extend(args.input_files)

    # Ensure at least one file was provided
    if not all_files:
        parser.error("at least one request YAML file must be provided.")

    # Deduplicate while preserving order
    seen = set()
    files: List[str] = []
    for f in all_files:
        if f not in seen:
            seen.add(f)
            files.append(f)
            
    in_path = Path(args.input_path)
    out_dir = Path(args.out_dir)

    if not in_path.exists():
        print(f"ERROR: input file does not exist: {in_path}", file=sys.stderr)
        return 2

    normalized = load_json(in_path)
    plan_items = build_plan_items(normalized)

    try:
        auth_cfg, planner_cfg = read_config_from_env()
    except Exception as e:
        plan_payload = {
            "generated_at": now_iso(),
            "error": f"Config error: {e}",
            "counts": {"fail": len(plan_items)},
            "items": [asdict(it) for it in plan_items],
        }
        write_json(out_dir / "plan.json", plan_payload)
        write_text(out_dir / "plan_report.md", f"# Plan Report\n\nConfig error: {e}\n")
        return 2

    api = BamApiClient(auth_cfg)
    try:
        api.login()
    except Exception as e:
        write_text(out_dir / "plan_report.md", f"# Plan Report\n\nBAM login failed: {e}\n")
        write_json(out_dir / "plan.json", {"generated_at": now_iso(), "error": f"login failed: {e}", "items": []})
        return 2

    adapter = BlueCatAdapter(api)
    planner = Planner(adapter, planner_cfg)

    planned: List[PlanItem] = []
    for it in plan_items:
        planned.append(planner.plan_item(it))

    counts = summarize(planned)

    plan_payload = {
        "generated_at": now_iso(),
        "counts": counts,
        "items": [asdict(it) for it in planned],
    }
    write_json(out_dir / "plan.json", plan_payload)
    write_text(out_dir / "plan_report.md", render_plan_report(planned, counts))

    return 2 if counts.get("fail", 0) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
