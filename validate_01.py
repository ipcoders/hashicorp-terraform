#!/usr/bin/env python3
"""
Validate + normalize BlueCat change request YAML files using Pydantic (MVP: TXT only).

Why this script exists
----------------------
This script ONLY validates structure and normalizes user input (lowercase, defaults, trimming).
It does NOT talk to BlueCat, and it does NOT decide create/skip/update/delete based on current state.
That state-aware logic belongs to later stages (Plan/Apply).

Current MVP contract (TXT only)
-------------------------------
Top level:
- user_email: required
- actions: required (non-empty list)

Action:
- action: create | update | delete
- view: optional, defaults to "internal"
- labels: optional, defaults to []
- records: required (non-empty list)

TXT record:
- type: "txt"
- zone: required string
- name: required string
- text: required string
- new_text: required ONLY when action == update

Important design note (RRset-friendly)
--------------------------------------
We treat a single TXT "value" as an item uniquely identified by:
  (view, zone, name, type, text)

That means:
- Multiple TXT values under the same name are allowed (RRset semantics).
- Delete and update target a specific TXT value (requires text).
- Update is modeled as "replace old value with new value" (text -> new_text).

Outputs:
- out/normalized_requests.json
- out/validation_report.md

Exit code:
- 0 if valid
- 2 if any validation errors
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

import yaml
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator, model_validator


def now_iso() -> str:
    """UTC timestamp for artifact metadata."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -----------------------------
# Models (TXT-only MVP)
# -----------------------------

RecordType = Literal["txt"]
ActionType = Literal["create", "update", "delete"]


class TXTRecord(BaseModel):
    """
    Represents a single TXT value under an owner name (NOT the entire RRset).

    Fields:
    - text: the current/target TXT value for create/delete, and "old" value for update.
    - new_text: the replacement value for update.
    """
    type: RecordType = Field(..., description="Record type (MVP: txt)")
    zone: str = Field(..., min_length=1, description="Zone name (e.g. auth.example.com)")
    name: str = Field(..., min_length=1, description="Relative record name within the zone")
    text: str = Field(..., min_length=1, description="TXT value (old/current for update, target for create/delete)")
    new_text: Optional[str] = Field(None, description="Replacement TXT value (update only)")

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: Any) -> Any:
        # Normalize user input like "TXT" -> "txt"
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("zone", "name", "text", "new_text", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
        # Ensure we don't accept invisible whitespace-only values.
        return v.strip() if isinstance(v, str) else v


class Action(BaseModel):
    """
    One group of operations (e.g., create multiple TXT values).
    Labels are optional metadata that later stages may include in reports / change-control notes.
    """
    action: ActionType
    records: List[TXTRecord] = Field(..., min_length=1)
    view: str = Field(default="internal")
    labels: List[str] = Field(default_factory=list)

    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("view", mode="before")
    @classmethod
    def normalize_view(cls, v: Any) -> Any:
        # Treat missing or null view as internal.
        if v is None:
            return "internal"
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("labels", mode="before")
    @classmethod
    def normalize_labels(cls, v: Any) -> Any:
        # Allow labels: null -> []
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
    def enforce_action_record_rules(self) -> "Action":
        """
        Enforce per-action requirements.

        create:
          - requires text (already required by model)
          - new_text MUST NOT be provided

        update:
          - requires text (old/current)
          - requires new_text (replacement)

        delete:
          - requires text
          - new_text MUST NOT be provided
        """
        for idx, r in enumerate(self.records):
            if self.action in ("create", "delete"):
                if r.new_text is not None and r.new_text != "":
                    raise ValueError(f"records[{idx}].new_text is not allowed for action: {self.action}")

            if self.action == "update":
                if r.new_text is None or r.new_text.strip() == "":
                    raise ValueError(f"records[{idx}].new_text is required for action: update")

        return self


class RequestFile(BaseModel):
    user_email: EmailStr
    actions: List[Action] = Field(..., min_length=1)

    @model_validator(mode="after")
    def cross_checks(self) -> "RequestFile":
        """
        File-level checks to prevent contradictory instructions within the same YAML file.

        TXT item key (RRset-friendly):
          (view, zone, name, type, text)

        We block:
        - create and delete of the same item in the same file
        - update and delete of the same item in the same file
        - multiple updates for the same old value but with different new_text
        - exact duplicates of the same instruction
        """
        created: set[Tuple[str, str, str, str, str]] = set()
        deleted: set[Tuple[str, str, str, str, str]] = set()
        updated_to: Dict[Tuple[str, str, str, str, str], str] = {}

        seen_dupes: set = set()

        for a in self.actions:
            for r in a.records:
                item_key = (a.view, r.zone, r.name, r.type, r.text)

                # Exact duplicate protection (same action + same item + same new_text)
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

        return self


# -----------------------------
# IO + Reporting
# -----------------------------

def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def write_outputs(out_dir: Path, normalized_requests: List[Dict[str, Any]], errors: List[str], warnings: List[str]) -> None:
    """Write machine + human artifacts."""
    out_dir.mkdir(parents=True, exist_ok=True)

    norm_path = out_dir / "normalized_requests.json"
    with norm_path.open("w", encoding="utf-8") as f:
        json.dump(
            {"generated_at": now_iso(), "count": len(normalized_requests), "requests": normalized_requests},
            f,
            indent=2,
        )

    rep_path = out_dir / "validation_report.md"
    with rep_path.open("w", encoding="utf-8") as f:
        f.write("# Validation Report\n\n")
        f.write(f"- Generated: `{now_iso()}`\n")
        f.write(f"- Files processed: `{len(normalized_requests)}`\n")
        f.write(f"- Errors: `{len(errors)}`\n")
        f.write(f"- Warnings: `{len(warnings)}`\n\n")

        if errors:
            f.write("## Errors\n\n")
            for e in errors:
                f.write(f"- **ERROR** {e}\n")
            f.write("\n")

        if warnings:
            f.write("## Warnings\n\n")
            for w in warnings:
                f.write(f"- **WARN** {w}\n")
            f.write("\n")

        if not errors and not warnings:
            f.write("No issues found.\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", help="Request YAML files to validate (e.g. requests/foo.yml)")
    parser.add_argument("--out", default="out", help="Output directory (default: out)")
    args = parser.parse_args()

    errors: List[str] = []
    warnings: List[str] = []
    normalized: List[Dict[str, Any]] = []

    for f in args.files:
        p = Path(f)

        if not p.exists():
            errors.append(f"`{f}`: file does not exist")
            continue
        if p.suffix.lower() not in {".yml", ".yaml"}:
            errors.append(f"`{f}`: file extension must be .yml or .yaml")
            continue

        raw = load_yaml(p)
        if raw is None:
            errors.append(f"`{f}`: empty or invalid YAML")
            continue

        try:
            req = RequestFile.model_validate(raw)
        except ValidationError as ve:
            for e in ve.errors():
                loc = ".".join(str(x) for x in e.get("loc", [])) or "(root)"
                msg = e.get("msg", "validation error")
                errors.append(f"`{f}` :: `{loc}` â€” {msg}")
            continue
        except ValueError as ve:
            errors.append(f"`{f}` :: (root) â€” {str(ve)}")
            continue

        # Practical MVP warning: update with identical values will become a SKIP later.
        for ai, a in enumerate(req.actions):
            if a.action == "update":
                for ri, r in enumerate(a.records):
                    if (r.text or "").strip() == (r.new_text or "").strip():
                        warnings.append(
                            f"`{f}` :: `actions[{ai}].records[{ri}]` â€” update has text == new_text; "
                            f"this will be skipped later (noop)."
                        )

        normalized.append(
            {
                "request_key": str(p).replace("\\", "/"),
                "user_email": str(req.user_email),
                "actions": [a.model_dump() for a in req.actions],
            }
        )

    out_dir = Path(args.out)
    write_outputs(out_dir, normalized, errors, warnings)

    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
