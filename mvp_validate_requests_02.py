#!/usr/bin/env python3
"""
Validate + normalize BlueCat change request YAML files.

Current supported objects:
- records:
  - TXT only
- ipam:
  - IPv4 network (create only)
  - IPv4 address
    - create:
      - explicit addresses
      - next available addresses
    - delete:
      - explicit addresses

This stage validates structure and normalizes input only.
It does NOT talk to BlueCat and does NOT make state-aware decisions.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import yaml
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator, model_validator


def now_iso() -> str:
    """UTC timestamp for artifact metadata."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -----------------------------
# Models
# -----------------------------

RecordType = Literal["txt"]
IpamType = Literal["ipv4_network", "ipv4_address"]
ActionType = Literal["create", "update", "delete"]


class TXTRecord(BaseModel):
    """
    Represents a single TXT value under an owner name (NOT the entire RRset).
    """
    type: RecordType = Field(..., description="Record type (MVP: txt)")
    zone: str = Field(..., min_length=1, description="Zone name (e.g. auth.example.com)")
    name: str = Field(..., min_length=1, description="Relative record name within the zone")
    text: str = Field(..., min_length=1, description="TXT value (old/current for update, target for create/delete)")
    new_text: Optional[str] = Field(None, description="Replacement TXT value (update only)")

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("zone", "name", "text", "new_text", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
        return v.strip() if isinstance(v, str) else v


class IPv4NetworkObject(BaseModel):
    """
    Create-only IPv4 network request.

    Users provide:
    - configuration: logical configuration name (e.g. DRE, MGIC INT)
    - parent_block: existing parent block range in CIDR form
    - range: desired network CIDR
    """
    type: Literal["ipv4_network"] = Field(..., description="IPAM object type (MVP: ipv4_network)")
    configuration: str = Field(..., min_length=1, description="Configuration name (e.g. DRE, MGIC INT)")
    parent_block: str = Field(..., min_length=1, description="Existing parent block range (e.g. 192.169.0.0/16)")
    range: str = Field(..., min_length=1, description="Desired IPv4 network range (e.g. 192.169.64.0/18)")

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("configuration", "parent_block", "range", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
        return v.strip() if isinstance(v, str) else v


class IPv4AddressObject(BaseModel):
    """
    IPv4 address request.

    Supported patterns:
    - create with explicit addresses
    - create with next available addresses
    - delete with explicit addresses
    """
    type: Literal["ipv4_address"] = Field(..., description="IPAM object type (MVP: ipv4_address)")
    configuration: str = Field(..., min_length=1, description="Configuration name (e.g. DRE, MGIC INT)")
    parent_network: str = Field(..., min_length=1, description="Existing parent network range (e.g. 192.170.0.0/18)")
    addresses: List[str] = Field(default_factory=list, description="Explicit IPv4 addresses")
    next_available_addresses: Optional[bool] = Field(
        None,
        description="If true, request next available IPv4 addresses inside the parent network"
    )
    next_available_count: Optional[int] = Field(
        None,
        description="Number of next available IPv4 addresses to request (default: 1, max: 10)"
    )

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("configuration", "parent_network", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
        return v.strip() if isinstance(v, str) else v

    @field_validator("addresses", mode="before")
    @classmethod
    def normalize_addresses(cls, v: Any) -> Any:
        if v is None:
            return []
        return v

    @field_validator("addresses")
    @classmethod
    def validate_addresses(cls, v: List[Any]) -> List[str]:
        if not isinstance(v, list):
            raise ValueError("addresses must be a list of non-empty strings")
        cleaned: List[str] = []
        for item in v:
            if not isinstance(item, str) or item.strip() == "":
                raise ValueError("addresses must contain only non-empty strings")
            cleaned.append(item.strip())
        return cleaned

    @field_validator("next_available_addresses", mode="before")
    @classmethod
    def normalize_next_available_flag(cls, v: Any) -> Any:
        if isinstance(v, str):
            lowered = v.strip().lower()
            if lowered in {"true", "yes"}:
                return True
            if lowered in {"false", "no"}:
                return False
        return v

    @field_validator("next_available_count", mode="before")
    @classmethod
    def normalize_next_available_count(cls, v: Any) -> Any:
        if v == "":
            return None
        return v


IpamObject = Union[IPv4NetworkObject, IPv4AddressObject]


class Action(BaseModel):
    """
    One group of requested operations.

    Current supported sections:
    - records: TXT record operations
    - ipam:
      - ipv4_network (create only)
      - ipv4_address (create/delete)
    """
    action: ActionType
    records: List[TXTRecord] = Field(default_factory=list)
    ipam: List[IpamObject] = Field(default_factory=list)
    view: str = Field(default="internal")
    labels: List[str] = Field(default_factory=list)

    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("view", mode="before")
    @classmethod
    def normalize_view(cls, v: Any) -> Any:
        if v is None:
            return "internal"
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("labels", mode="before")
    @classmethod
    def normalize_labels(cls, v: Any) -> Any:
        if v is None:
            return []
        return v

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, v: List[Any]) -> List[str]:
        if not isinstance(v, list):
            raise ValueError("labels must be a list of strings")
        cleaned: List[str] = []
        for item in v:
            if not isinstance(item, str) or item.strip() == "":
                raise ValueError("labels must contain only non-empty strings")
            cleaned.append(item.strip())
        return cleaned

    @model_validator(mode="after")
    def enforce_action_rules(self) -> "Action":
        """
        Enforce per-action requirements.

        Common:
          - at least one of records or ipam must be non-empty

        TXT record rules:
          create:
            - requires text
            - new_text MUST NOT be provided

          update:
            - requires text
            - requires new_text

          delete:
            - requires text
            - new_text MUST NOT be provided

        IPAM rules:
          ipv4_network:
            - supports only action=create

          ipv4_address:
            create manual mode:
              - addresses required
              - next_available_addresses forbidden
              - next_available_count forbidden

            create next-available mode:
              - next_available_addresses must be true
              - addresses must be empty
              - next_available_count default=1, max=10

            delete:
              - addresses required
              - next_available_addresses forbidden
              - next_available_count forbidden
        """
        if not self.records and not self.ipam:
            raise ValueError("each action must contain at least one non-empty section: records or ipam")

        # TXT validation
        for idx, r in enumerate(self.records):
            if self.action in ("create", "delete"):
                if r.new_text is not None and r.new_text != "":
                    raise ValueError(f"records[{idx}].new_text is not allowed for action: {self.action}")

            if self.action == "update":
                if r.new_text is None or r.new_text.strip() == "":
                    raise ValueError(f"records[{idx}].new_text is required for action: update")

        # IPAM validation
        for idx, obj in enumerate(self.ipam):
            if isinstance(obj, IPv4NetworkObject):
                if self.action != "create":
                    raise ValueError("ipv4_network currently supports only action: create")

            elif isinstance(obj, IPv4AddressObject):
                if self.action == "create":
                    has_addresses = len(obj.addresses) > 0
                    wants_next = obj.next_available_addresses is True

                    if has_addresses and wants_next:
                        raise ValueError(
                            f"ipam[{idx}] for ipv4_address cannot use both addresses and next_available_addresses"
                        )

                    if has_addresses:
                        if obj.next_available_count is not None:
                            raise ValueError(
                                f"ipam[{idx}].next_available_count is not allowed when addresses are provided"
                            )
                        if obj.next_available_addresses not in (None, False):
                            raise ValueError(
                                f"ipam[{idx}].next_available_addresses must not be true when addresses are provided"
                            )

                    elif wants_next:
                        if obj.next_available_count is None:
                            obj.next_available_count = 1
                        if obj.next_available_count < 1:
                            raise ValueError(f"ipam[{idx}].next_available_count must be at least 1")
                        if obj.next_available_count > 10:
                            raise ValueError(f"ipam[{idx}].next_available_count must not exceed 10")

                    else:
                        raise ValueError(
                            f"ipam[{idx}] for ipv4_address create must use either explicit addresses "
                            f"or next_available_addresses: true"
                        )

                elif self.action == "delete":
                    if not obj.addresses:
                        raise ValueError(f"ipam[{idx}].addresses is required for ipv4_address delete")
                    if obj.next_available_addresses not in (None, False):
                        raise ValueError(
                            f"ipam[{idx}].next_available_addresses is not allowed for ipv4_address delete"
                        )
                    if obj.next_available_count is not None:
                        raise ValueError(
                            f"ipam[{idx}].next_available_count is not allowed for ipv4_address delete"
                        )

                else:
                    raise ValueError("ipv4_address currently supports only action: create or delete")

        return self


class RequestFile(BaseModel):
    user_email: EmailStr
    actions: List[Action] = Field(..., min_length=1)

    @model_validator(mode="after")
    def cross_checks(self) -> "RequestFile":
        """
        File-level checks to prevent contradictory or duplicate instructions.

        TXT item key:
          (view, zone, name, type, text)

        IPv4 network key:
          (configuration, parent_block, range, type)

        IPv4 address explicit key:
          (configuration, parent_network, address, type)
        """
        created: set[Tuple[str, str, str, str, str]] = set()
        deleted: set[Tuple[str, str, str, str, str]] = set()
        updated_to: Dict[Tuple[str, str, str, str, str], str] = {}

        seen_dupes: set = set()
        seen_ipam_network_creates: set[Tuple[str, str, str, str]] = set()

        created_ipv4_addresses: set[Tuple[str, str, str, str]] = set()
        deleted_ipv4_addresses: set[Tuple[str, str, str, str]] = set()
        seen_next_available_requests: set[Tuple[str, str, int, str]] = set()

        for a in self.actions:
            # TXT checks
            for r in a.records:
                item_key = (a.view, r.zone, r.name, r.type, r.text)

                dupe_key = (a.action, *item_key, r.new_text if isinstance(r.new_text, str) else None)
                if dupe_key in seen_dupes:
                    raise ValueError(f"Duplicate entry detected: {dupe_key}")
                seen_dupes.add(dupe_key)

                if a.action == "create":
                    if item_key in deleted:
                        raise ValueError(f"Conflicting intent: create and delete for the same TXT value in one file: {item_key}")
                    created.add(item_key)

                elif a.action == "delete":
                    if item_key in created:
                        raise ValueError(f"Conflicting intent: create and delete for the same TXT value in one file: {item_key}")
                    if item_key in updated_to:
                        raise ValueError(f"Conflicting intent: update and delete for the same TXT value in one file: {item_key}")
                    deleted.add(item_key)

                elif a.action == "update":
                    if item_key in deleted:
                        raise ValueError(f"Conflicting intent: update and delete for the same TXT value in one file: {item_key}")
                    new_val = (r.new_text or "").strip()
                    prev = updated_to.get(item_key)
                    if prev and prev != new_val:
                        raise ValueError(
                            f"Conflicting intent: multiple updates for same old TXT value with different new_text. "
                            f"Record={item_key} new_text='{prev}' vs '{new_val}'"
                        )
                    updated_to[item_key] = new_val

            # IPAM checks
            for obj in a.ipam:
                if isinstance(obj, IPv4NetworkObject):
                    net_key = (obj.configuration, obj.parent_block, obj.range, obj.type)
                    if net_key in seen_ipam_network_creates:
                        raise ValueError(f"Duplicate ipv4_network create entry detected: {net_key}")
                    seen_ipam_network_creates.add(net_key)

                elif isinstance(obj, IPv4AddressObject):
                    if a.action == "create":
                        if obj.addresses:
                            for address in obj.addresses:
                                addr_key = (obj.configuration, obj.parent_network, address, obj.type)
                                if addr_key in deleted_ipv4_addresses:
                                    raise ValueError(
                                        f"Conflicting intent: create and delete for the same IPv4 address in one file: {addr_key}"
                                    )
                                if addr_key in created_ipv4_addresses:
                                    raise ValueError(f"Duplicate ipv4_address create entry detected: {addr_key}")
                                created_ipv4_addresses.add(addr_key)

                        elif obj.next_available_addresses is True:
                            req_key = (
                                obj.configuration,
                                obj.parent_network,
                                obj.next_available_count or 1,
                                obj.type,
                            )
                            if req_key in seen_next_available_requests:
                                raise ValueError(f"Duplicate next-available ipv4_address create entry detected: {req_key}")
                            seen_next_available_requests.add(req_key)

                    elif a.action == "delete":
                        for address in obj.addresses:
                            addr_key = (obj.configuration, obj.parent_network, address, obj.type)
                            if addr_key in created_ipv4_addresses:
                                raise ValueError(
                                    f"Conflicting intent: create and delete for the same IPv4 address in one file: {addr_key}"
                                )
                            if addr_key in deleted_ipv4_addresses:
                                raise ValueError(f"Duplicate ipv4_address delete entry detected: {addr_key}")
                            deleted_ipv4_addresses.add(addr_key)

        return self


# -----------------------------
# IO + Reporting
# -----------------------------

def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def write_outputs(
    out_dir: Path,
    normalized_requests: List[Dict[str, Any]],
    errors: List[str],
    warnings: List[str],
    file_results: List[Dict[str, Any]],
) -> None:
    """Write machine + human artifacts."""
    out_dir.mkdir(parents=True, exist_ok=True)

    norm_path = out_dir / "normalized_requests.json"
    with norm_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": now_iso(),
                "count": len(normalized_requests),
                "requests": normalized_requests,
            },
            f,
            indent=2,
        )

    rep_path = out_dir / "validation_report.md"
    with rep_path.open("w", encoding="utf-8") as f:
        f.write("# Validation Report\n\n")
        f.write(f"- Generated: `{now_iso()}`\n")
        f.write(f"- Files received: `{len(file_results)}`\n")
        f.write(f"- Files normalized: `{len(normalized_requests)}`\n")
        f.write(f"- Errors: `{len(errors)}`\n")
        f.write(f"- Warnings: `{len(warnings)}`\n\n")

        if file_results:
            f.write("## File Results\n\n")
            for result in file_results:
                file_name = result["file"]
                file_errors = result["errors"]
                file_warnings = result["warnings"]

                status = "INVALID" if file_errors else "VALID"
                f.write(f"### `{file_name}`\n\n")
                f.write(f"- Status: **{status}**\n")
                f.write(f"- Errors: `{len(file_errors)}`\n")
                f.write(f"- Warnings: `{len(file_warnings)}`\n")

                if file_errors:
                    f.write("\n#### Errors\n\n")
                    for err in file_errors:
                        f.write(f"- **ERROR** {err}\n")

                if file_warnings:
                    f.write("\n#### Warnings\n\n")
                    for warn in file_warnings:
                        f.write(f"- **WARN** {warn}\n")

                f.write("\n")

        if errors:
            f.write("## All Errors\n\n")
            for e in errors:
                f.write(f"- **ERROR** {e}\n")
            f.write("\n")

        if warnings:
            f.write("## All Warnings\n\n")
            for w in warnings:
                f.write(f"- **WARN** {w}\n")
            f.write("\n")

        if not errors and not warnings:
            f.write("No issues found.\n")


def main() -> int:
    parser = argparse.ArgumentParser()

    # Positional files (original behavior)
    parser.add_argument(
        "files",
        nargs="*",
        help="Request YAML files to validate (positional form)",
    )

    # Optional --in flag (alternative style)
    parser.add_argument(
        "--in",
        dest="input_files",
        nargs="+",
        default=None,
        help="Request YAML files to validate (flag form)",
    )

    parser.add_argument(
        "--out",
        default="out",
        help="Output directory (default: out)",
    )

    args = parser.parse_args()

    all_files: List[str] = []
    if args.files:
        all_files.extend(args.files)
    if args.input_files:
        all_files.extend(args.input_files)

    if not all_files:
        parser.error("at least one request YAML file must be provided")

    seen = set()
    files: List[str] = []
    for f in all_files:
        if f not in seen:
            seen.add(f)
            files.append(f)

    errors: List[str] = []
    warnings: List[str] = []
    normalized: List[Dict[str, Any]] = []
    file_results: List[Dict[str, Any]] = []

    for f in files:
        p = Path(f)
        file_errors: List[str] = []
        file_warnings: List[str] = []

        if not p.exists():
            msg = f"`{f}`: file does not exist"
            errors.append(msg)
            file_errors.append(msg)
            file_results.append({"file": f, "errors": file_errors, "warnings": file_warnings})
            continue

        if p.suffix.lower() not in {".yml", ".yaml"}:
            msg = f"`{f}`: file extension must be .yml or .yaml"
            errors.append(msg)
            file_errors.append(msg)
            file_results.append({"file": f, "errors": file_errors, "warnings": file_warnings})
            continue

        raw = load_yaml(p)
        if raw is None:
            msg = f"`{f}`: empty or invalid YAML"
            errors.append(msg)
            file_errors.append(msg)
            file_results.append({"file": f, "errors": file_errors, "warnings": file_warnings})
            continue

        try:
            req = RequestFile.model_validate(raw)
        except ValidationError as ve:
            for e in ve.errors():
                loc = ".".join(str(x) for x in e.get("loc", [])) or "(root)"
                msg = e.get("msg", "validation error")
                full_msg = f"`{f}` :: `{loc}` - {msg}"
                errors.append(full_msg)
                file_errors.append(full_msg)

            file_results.append({"file": f, "errors": file_errors, "warnings": file_warnings})
            continue
        except ValueError as ve:
            full_msg = f"`{f}` :: (root) - {str(ve)}"
            errors.append(full_msg)
            file_errors.append(full_msg)
            file_results.append({"file": f, "errors": file_errors, "warnings": file_warnings})
            continue

        for ai, a in enumerate(req.actions):
            for ri, r in enumerate(a.records):
                if a.action == "update":
                    if (r.text or "").strip() == (r.new_text or "").strip():
                        warn_msg = (
                            f"`{f}` :: `actions[{ai}].records[{ri}]` - update has text == new_text; "
                            "this will be skipped later (noop)."
                        )
                        warnings.append(warn_msg)
                        file_warnings.append(warn_msg)

        normalized.append(
            {
                "request_key": str(p).replace("\\", "/"),
                "user_email": str(req.user_email),
                "actions": [a.model_dump() for a in req.actions],
            }
        )

        file_results.append({"file": f, "errors": file_errors, "warnings": file_warnings})

    out_dir = Path(args.out)
    write_outputs(out_dir, normalized, errors, warnings, file_results)

    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
