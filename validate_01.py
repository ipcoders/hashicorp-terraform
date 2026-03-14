#!/usr/bin/env python3
"""
------------------------------------------------------------------------------
Script: validate_requests.py
------------------------------------------------------------------------------

Purpose
------------------------------------------------------------------------------
This script validates and normalizes BlueCat change request YAML files before
they enter later stages of the automation pipeline.

The script ensures that request files follow the expected schema and contain
logically consistent operations. It performs structural validation and input
normalization only.

Important:
This script does NOT communicate with BlueCat and does NOT evaluate the
current DNS state. Decisions such as create/skip/update/delete based on
existing records are handled in later pipeline stages (Plan/Apply).

The goal of this stage is to guarantee that user-provided YAML files are:

    - structurally valid
    - internally consistent
    - normalized for downstream processing


------------------------------------------------------------------------------
Input
------------------------------------------------------------------------------
The script accepts one or more request YAML files as positional arguments:

    validate_requests.py requests/example.yml requests/test.yaml

Each file must:

    - exist on disk
    - have extension .yml or .yaml
    - contain valid YAML


------------------------------------------------------------------------------
Data Model (TXT-only MVP)
------------------------------------------------------------------------------

Top-level structure:

    user_email: required
    actions: required (non-empty list)

Action structure:

    action: create | update | delete
    view: optional, defaults to "internal"
    labels: optional metadata list (defaults to [])
    records: required (non-empty list)

TXT record structure:

    type: "txt"
    zone: required string
    name: required string
    text: required string
    new_text: required ONLY when action == update


------------------------------------------------------------------------------
Normalization Behavior
------------------------------------------------------------------------------
User input is normalized before being passed downstream.

The script automatically:

    - converts record type to lowercase ("TXT" -> "txt")
    - converts action to lowercase
    - converts view to lowercase
    - trims whitespace from strings
    - converts null labels to empty list []
    - trims whitespace inside label values

These transformations ensure that later pipeline stages operate on clean,
consistent data.


------------------------------------------------------------------------------
TXT Record Design (RRset-friendly)
------------------------------------------------------------------------------
TXT records are treated as individual values within a DNS RRset.

Each TXT value is uniquely identified by:

    (view, zone, name, type, text)

This allows multiple TXT values under the same name.

Examples:

    _acme-challenge.example.com TXT "token1"
    _acme-challenge.example.com TXT "token2"

These are treated as separate items.

Operation semantics:

Create:
    adds a TXT value

Delete:
    removes a specific TXT value

Update:
    replaces a TXT value
    (text -> new_text)


------------------------------------------------------------------------------
Action Validation Rules
------------------------------------------------------------------------------

CREATE
    - text is required
    - new_text MUST NOT be provided

UPDATE
    - text is required (old value)
    - new_text is required (replacement value)

DELETE
    - text is required
    - new_text MUST NOT be provided


------------------------------------------------------------------------------
File-Level Consistency Checks
------------------------------------------------------------------------------
The script prevents contradictory instructions within the same YAML file.

Using the TXT item key:

    (view, zone, name, type, text)

The following situations are blocked:

    - create AND delete of the same TXT value in one file
    - update AND delete of the same TXT value in one file
    - multiple updates of the same TXT value with different new_text
    - exact duplicate instructions

These checks prevent ambiguous or conflicting change requests.


------------------------------------------------------------------------------
Warnings
------------------------------------------------------------------------------
Some conditions are allowed but produce warnings.

Example:

    update where text == new_text

This represents a no-op change and will later be skipped during the Plan
stage, but the request is still considered valid.


------------------------------------------------------------------------------
Outputs
------------------------------------------------------------------------------

1) normalized_requests.json

Machine-readable artifact containing normalized request objects.

Structure:

    {
      "generated_at": "<UTC timestamp>",
      "count": <number_of_requests>,
      "requests": [...]
    }

Each request entry contains:

    - request_key (original file path)
    - user_email
    - normalized actions


2) validation_report.md

Human-readable validation report containing:

    - generation timestamp
    - number of processed files
    - validation errors
    - warnings
    - summary status


------------------------------------------------------------------------------
Exit Codes
------------------------------------------------------------------------------

Exit 0
    Validation successful (no errors)

Exit 2
    One or more validation errors detected


------------------------------------------------------------------------------
Design Philosophy
------------------------------------------------------------------------------
This validator intentionally performs only schema validation and logical
consistency checks.

It does NOT:

    - check whether DNS records already exist
    - determine whether operations are necessary
    - communicate with BlueCat APIs

Those responsibilities belong to later pipeline stages that have access
to live infrastructure state.

By keeping validation deterministic and state-independent, the pipeline
remains predictable and easier to audit.
------------------------------------------------------------------------------
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
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("zone", "name", "text", "new_text", mode="before")
    @classmethod
    def strip_strings(cls, v: Any) -> Any:
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

                dupe_key = (a.action, *item_key, r.new_text if isinstance(r.new_text, str) else None)
                if dupe_key in seen_dupes:
                    raise ValueError(f"Duplicate entry detected: {dupe_key}")
                seen_dupes.add(dupe_key)

                if a.action == "create":
                    if item_key in deleted:
                        raise ValueError(
                            f"Conflicting intent: create and delete for the same TXT value in one file: {item_key}"
                        )
                    created.add(item_key)

                elif a.action == "delete":
                    if item_key in created:
                        raise ValueError(
                            f"Conflicting intent: create and delete for the same TXT value in one file: {item_key}"
                        )
                    if item_key in updated_to:
                        raise ValueError(
                            f"Conflicting intent: update and delete for the same TXT value in one file: {item_key}"
                        )
                    deleted.add(item_key)

                elif a.action == "update":
                    if item_key in deleted:
                        raise ValueError(
                            f"Conflicting intent: update and delete for the same TXT value in one file: {item_key}"
                        )
                    new_val = (r.new_text or "").strip()
                    prev = updated_to.get(item_key)
                    if prev and prev != new_val:
                        raise ValueError(
                            "Conflicting intent: multiple updates for same old TXT value with different new_text. "
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
    parser.add_argument("files", nargs="+", help="Request YAML files to validate (e.g. requests/foo.yml)")
    parser.add_argument("--out", default="out", help="Output directory (default: out)")
    args = parser.parse_args()

    errors: List[str] = []
    warnings: List[str] = []
    normalized: List[Dict[str, Any]] = []
    file_results: List[Dict[str, Any]] = []

    for f in args.files:
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
                full_msg = f"`{f}` :: `{loc}` — {msg}"
                errors.append(full_msg)
                file_errors.append(full_msg)

            file_results.append({"file": f, "errors": file_errors, "warnings": file_warnings})
            continue
        except ValueError as ve:
            full_msg = f"`{f}` :: (root) — {str(ve)}"
            errors.append(full_msg)
            file_errors.append(full_msg)
            file_results.append({"file": f, "errors": file_errors, "warnings": file_warnings})
            continue

        for ai, a in enumerate(req.actions):
            if a.action == "update":
                for ri, r in enumerate(a.records):
                    if (r.text or "").strip() == (r.new_text or "").strip():
                        warn_msg = (
                            f"`{f}` :: `actions[{ai}].records[{ri}]` — update has text == new_text; "
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
