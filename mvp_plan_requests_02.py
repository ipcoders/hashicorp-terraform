#!/usr/bin/env python3
"""
Plan stage (read-only) for BlueCat GitOps MVP.

Supported objects:
- records:
  - TXT
- ipam:
  - IPv4 network (create only)
  - IPv4 address
    - create:
      - explicit addresses
      - next available addresses
    - delete:
      - explicit addresses

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
import ipaddress
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


@dataclass(frozen=True)
class IPv4AddressRef:
    configuration_id: str
    configuration_name: str
    parent_network: str
    parent_network_id: str
    address: str
    address_id: str
    state: str


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

    def ipv4_network_container_match(self, configuration_id: str, cidr: str) -> List[NetworkRef]:
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

    def ipv4_blocks_containing_range(self, configuration_id: str, cidr: str) -> List[BlockRef]:
        """
        Return all blocks in the given configuration whose range fully contains the requested CIDR.
        """
        target = ipaddress.ip_network(cidr, strict=True)

        data = self.api.request("GET", "/api/v2/blocks", params={"filter": "type:eq('IPv4Block')"})
        items = data.get("data") or []

        matches: List[BlockRef] = []
        for item in items:
            cfg = item.get("configuration") or {}
            if str(cfg.get("id", "")) != str(configuration_id):
                continue

            block_range = str(item.get("range", ""))
            if not block_range:
                continue

            try:
                block_net = ipaddress.ip_network(block_range, strict=True)
            except ValueError:
                continue

            if target.subnet_of(block_net):
                matches.append(
                    BlockRef(
                        configuration_id=str(cfg.get("id", "")),
                        configuration_name=str(cfg.get("name", "")),
                        range=block_range,
                        block_id=str(item["id"]),
                    )
                )

        return matches

    # ---- IPAM / IPv4 Addresses ----

    def ipv4_address_exact_match(self, configuration_id: str, parent_network_id: str, parent_network: str, address: str) -> List[IPv4AddressRef]:
        data = self.api.request(
            "GET",
            f"/api/v2/networks/{parent_network_id}/addresses",
            params={"filter": f"address:eq('{address}')"},
        )

        items = data.get("data") or []
        matches: List[IPv4AddressRef] = []

        for item in items:
            cfg = item.get("configuration") or {}
            if str(cfg.get("id", "")) != str(configuration_id):
                continue

            matches.append(
                IPv4AddressRef(
                    configuration_id=str(cfg.get("id", "")),
                    configuration_name=str(cfg.get("name", "")),
                    parent_network=parent_network,
                    parent_network_id=parent_network_id,
                    address=str(item.get("address", "")),
                    address_id=str(item["id"]),
                    state=str(item.get("state", "")),
                )
            )

        return matches

    def ipv4_available_addresses(self, parent_network_id: str, limit: int) -> List[str]:
        data = self.api.request(
            "GET",
            f"/api/v2/networks/{parent_network_id}/availableAddresses",
            params={"limit": limit},
        )

        items = data.get("data") or []
        return [str(item.get("address", "")) for item in items if item.get("address")]


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
    parent_network: str = ""
    parent_network_id: Optional[str] = None
    range: str = ""
    address: str = ""
    next_available_addresses: bool = False
    next_available_count: int = 0


class Planner:
    def __init__(self, adapter: BlueCatAdapter, cfg: PlannerConfig) -> None:
        self.adapter = adapter
        self.cfg = cfg

    def plan_item(self, item: PlanItem) -> PlanItem:
        if item.type == "txt":
            return self.plan_txt(item)
        if item.type == "ipv4_network":
            return self.plan_ipv4_network(item)
        if item.type == "ipv4_address":
            return self.plan_ipv4_address(item)
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
            parent_networks = self._safe_network_lookup(item.configuration_id, item.parent_block, item)
            if parent_networks:
                return self._fail(
                    item,
                    f"Invalid parent_block: {item.parent_block} exists as an IPv4Network, not an IPv4Block. "
                    "IPv4 networks can only be created under blocks.",
                )

            return self._fail(item, f"Parent block {item.parent_block} does not exist")

        if self.cfg.fail_on_ambiguous_match and len(parent_blocks) > 1:
            return self._fail(item, "Ambiguous match: more than one exact parent block found", {"match_count": len(parent_blocks)})

        containing_blocks = self._safe_containing_blocks_lookup(item.configuration_id, item.range, item)
        if containing_blocks is None:
            return item
        if len(containing_blocks) == 0:
            return self._fail(item, "No containing block exists for requested IPv4 network range")

        try:
            most_specific = min(
                containing_blocks,
                key=lambda b: ipaddress.ip_network(b.range, strict=True).num_addresses
            )
        except Exception as e:
            return self._fail(item, f"Unable to determine most specific containing block: {e}")

        if most_specific.range != item.parent_block:
            return self._fail(
                item,
                f"Requested parent block is not the most specific containing block; use parent_block={most_specific.range}",
                {
                    "requested_parent_block": item.parent_block,
                    "most_specific_parent_block": most_specific.range,
                    "most_specific_parent_block_id": most_specific.block_id,
                },
            )

        item.parent_block_id = most_specific.block_id

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

    def _safe_containing_blocks_lookup(self, configuration_id: str, cidr: str, item: PlanItem) -> Optional[List[BlockRef]]:
        try:
            matches = self.adapter.ipv4_blocks_containing_range(configuration_id=configuration_id, cidr=cidr)
        except Exception as e:
            updated = self._fail(item, f"Containing block lookup error: {e}")
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        return matches

    # ---- IPv4 Address ----

    def plan_ipv4_address(self, item: PlanItem) -> PlanItem:
        if item.action not in {"create", "delete"}:
            return self._fail(item, "ipv4_address currently supports only action=create or action=delete")

        if not item.configuration_id:
            return self._fail(item, f"Unsupported configuration name: {item.configuration}")

        parent_networks = self._safe_network_lookup(item.configuration_id, item.parent_network, item)
        if parent_networks is None:
            return item
        if len(parent_networks) == 0:
            return self._fail(item, f"Parent network {item.parent_network} does not exist")
        if self.cfg.fail_on_ambiguous_match and len(parent_networks) > 1:
            return self._fail(item, "Ambiguous match: more than one exact parent network found", {"match_count": len(parent_networks)})

        item.parent_network_id = parent_networks[0].network_id

        if item.action == "create":
            return self._plan_ipv4_address_create(item)
        return self._plan_ipv4_address_delete(item)

    def _plan_ipv4_address_create(self, item: PlanItem) -> PlanItem:
        parent_net = None
        try:
            parent_net = ipaddress.ip_network(item.parent_network, strict=True)
        except ValueError as e:
            return self._fail(item, f"Invalid parent_network CIDR: {e}")

        # Next available mode
        if item.next_available_addresses:
            count = item.next_available_count or 1
            available = self._safe_available_addresses_lookup(item.parent_network_id or "", count, item)
            if available is None:
                return item
            if len(available) < count:
                return self._fail(
                    item,
                    f"Parent network has insufficient available addresses; requested={count} available={len(available)}",
                    {"requested_count": count, "available_count": len(available)},
                )

            item.details = {
                "parent_network_id": item.parent_network_id,
                "configuration_id": item.configuration_id,
                "addresses": available[:count],
                "requested_count": count,
            }
            item.address = ",".join(available[:count])
            return self._create(item, "Requested next available IPv4 addresses are available; create is needed", item.details)

        # Explicit address mode
        if not item.address:
            return self._fail(item, "ipv4_address create requires an address or next-available mode")

        try:
            addr = ipaddress.ip_address(item.address)
        except ValueError as e:
            return self._fail(item, f"Invalid IPv4 address: {e}")

        if addr not in parent_net:
            return self._fail(item, f"Address {item.address} does not reside within parent_network {item.parent_network}")

        existing = self._safe_ipv4_address_lookup(
            item.configuration_id or "",
            item.parent_network_id or "",
            item.parent_network,
            item.address,
            item,
        )
        if existing is None:
            return item
        if len(existing) > 0:
            return self._fail(item, f"IPv4 address {item.address} already exists in parent network")

        return self._create(
            item,
            "Requested IPv4 address does not exist and belongs to the parent network; create is needed",
            {
                "parent_network_id": item.parent_network_id,
                "configuration_id": item.configuration_id,
                "address": item.address,
                "state": "STATIC",
            },
        )

    def _plan_ipv4_address_delete(self, item: PlanItem) -> PlanItem:
        if not item.address:
            return self._fail(item, "ipv4_address delete requires an explicit address")

        existing = self._safe_ipv4_address_lookup(
            item.configuration_id or "",
            item.parent_network_id or "",
            item.parent_network,
            item.address,
            item,
        )
        if existing is None:
            return item
        if len(existing) == 0:
            return self._fail(item, f"IPv4 address {item.address} does not exist in parent network")

        return self._delete(
            item,
            "IPv4 address exists; delete is needed",
            {
                "parent_network_id": item.parent_network_id,
                "configuration_id": item.configuration_id,
                "address": item.address,
                "address_id": existing[0].address_id,
            },
        )

    def _safe_ipv4_address_lookup(
        self,
        configuration_id: str,
        parent_network_id: str,
        parent_network: str,
        address: str,
        item: PlanItem,
    ) -> Optional[List[IPv4AddressRef]]:
        try:
            matches = self.adapter.ipv4_address_exact_match(
                configuration_id=configuration_id,
                parent_network_id=parent_network_id,
                parent_network=parent_network,
                address=address,
            )
        except Exception as e:
            updated = self._fail(item, f"IPv4 address lookup error: {e}")
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        if self.cfg.fail_on_ambiguous_match and len(matches) > 1:
            updated = self._fail(item, "Ambiguous match: more than one exact IPv4 address found", {"match_count": len(matches)})
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

        return matches

    def _safe_available_addresses_lookup(self, parent_network_id: str, count: int, item: PlanItem) -> Optional[List[str]]:
        try:
            return self.adapter.ipv4_available_addresses(parent_network_id=parent_network_id, limit=count)
        except Exception as e:
            updated = self._fail(item, f"Available IPv4 addresses lookup error: {e}")
            item.planned, item.reason, item.details = updated.planned, updated.reason, updated.details
            return None

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
                ipam_type = ipam_obj.get("type")
                configuration = str(ipam_obj.get("configuration", ""))

                if ipam_type == "ipv4_network":
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

                elif ipam_type == "ipv4_address":
                    addresses = ipam_obj.get("addresses") or []
                    next_available = bool(ipam_obj.get("next_available_addresses") is True)
                    next_count = int(ipam_obj.get("next_available_count") or 1)

                    # Create one PlanItem per address for explicit mode
                    if addresses:
                        for address in addresses:
                            items.append(
                                PlanItem(
                                    request_key=request_key,
                                    user_email=user_email,
                                    labels=labels,
                                    view="",
                                    type="ipv4_address",
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
                                    parent_network=str(ipam_obj.get("parent_network", "")),
                                    address=str(address),
                                )
                            )
                    else:
                        # Single PlanItem represents a next-available request batch
                        items.append(
                            PlanItem(
                                request_key=request_key,
                                user_email=user_email,
                                labels=labels,
                                view="",
                                type="ipv4_address",
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
                                parent_network=str(ipam_obj.get("parent_network", "")),
                                next_available_addresses=next_available,
                                next_available_count=next_count,
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

    if it.type == "ipv4_address":
        if it.next_available_addresses:
            return (
                f"`{it.type}` configuration=`{it.configuration}` parent_network=`{it.parent_network}` "
                f"next_available_count=`{it.next_available_count}` action=`{it.action}`"
            )
        return (
            f"`{it.type}` configuration=`{it.configuration}` parent_network=`{it.parent_network}` "
            f"address=`{it.address}` action=`{it.action}`"
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
    parser.add_argument("--in", dest="input_path", required=True, help="Input normalized_requests.json")
    parser.add_argument("--out", dest="out_dir", default="out", help="Output directory (default: out)")
    args = parser.parse_args()

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
  
