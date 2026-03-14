#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Script: discover_requests.sh
#
# Purpose
# ------------------------------------------------------------------------------
# This script analyzes a Git repository and determines which request files
# under the `requests/` directory should be processed by downstream workflows.
#
# It compares a target commit (`--head`) against a base commit (`--base`),
# detects file changes, and applies governance rules to files under the
# `requests/` directory.
#
# The script produces:
#
#   1) A list of request YAML files detected in the change set
#   2) A governance report describing all detected changes and violations
#
# This script is designed to run in CI pipelines to enforce repository
# governance rules before further automation is executed.
#
#
# ------------------------------------------------------------------------------
# Comparison Logic
# ------------------------------------------------------------------------------
# The script compares two commits:
#
#   HEAD_REF  -> the commit being evaluated (required)
#   BASE_REF  -> the commit to compare against (optional)
#
# If BASE_REF is not provided:
#
#   - If a previous commit exists, BASE_REF is automatically set to HEAD~1
#   - If the repository only has one commit, the script compares against the
#     empty tree and evaluates files introduced in the first commit.
#
#
# ------------------------------------------------------------------------------
# Change Detection
# ------------------------------------------------------------------------------
# The script retrieves changes using:
#
#   git diff --name-status BASE..HEAD
#
# or (for first commit):
#
#   git diff-tree --name-status HEAD
#
# Each change contains:
#
#   A = Added
#   M = Modified
#   D = Deleted
#   R = Renamed
#
#
# ------------------------------------------------------------------------------
# Governance Rules (Current Implementation)
# ------------------------------------------------------------------------------
#
# The following rules are applied ONLY to files under the `requests/` directory.
#
# Allowed:
#
#   - Added YAML files:
#       requests/*.yml
#       requests/*.yaml
#
#   - Modified YAML files:
#       requests/*.yml
#       requests/*.yaml
#
#   - Deleted files under requests/ (currently allowed and ignored).
#
#
# Violations:
#
#   - Any rename operation involving the `requests/` directory.
#
#   - Any file added or modified under `requests/` that does NOT end in:
#         .yml
#         .yaml
#
#   - Any unexpected Git change type under `requests/`.
#
#
# Files outside the `requests/` directory are logged in the report but are
# NOT validated by governance rules.
#
#
# ------------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------------
#
# 1) request_files.txt
#
#    Contains paths to request YAML files detected in the change set.
#    These correspond to files under `requests/` that were Added or Modified
#    and match the .yml/.yaml extension.
#
#    Format:
#
#       requests/example.yml
#       requests/test.yaml
#
#
# 2) governance_report.md
#
#    A human-readable Markdown report containing:
#
#       - Repository information
#       - Commit SHAs used for comparison
#       - Detected file changes
#       - Governance violations
#       - Summary of results
#
#
# ------------------------------------------------------------------------------
# Exit Codes
# ------------------------------------------------------------------------------
#
# Exit 0
#   Governance checks passed.
#
# Exit 3
#   Governance violations detected.
#
# Exit 2
#   Invalid arguments or usage error.
#
#
# ------------------------------------------------------------------------------
# Notes
# ------------------------------------------------------------------------------
#
# - The repository is cloned fresh for every run to ensure deterministic
#   behavior.
#
# - Deletions under `requests/` are currently allowed but ignored for request
#   processing (MVP behavior).
#
# - Only YAML request files (.yml / .yaml) are collected for downstream
#   processing.
#
# ------------------------------------------------------------------------------

set -euo pipefail

usage() {
cat <<'EOF'
Usage:
discover_requests.sh --repo-url <url> --head <ref> [--base <ref>] [--workdir <dir>] [--outdir <dir>]

Purpose:
Discover request YAML files under the `requests/` directory and enforce
governance rules on repository changes.

Required Arguments:
--repo-url   Git URL of the repository to analyze
--head       Commit SHA or ref representing the "new state" to evaluate

Optional Arguments:
--base       Commit SHA or ref to compare against
Default: previous commit (<head>~1) if it exists
If the repo has only one commit, the script compares against
the empty tree.

--workdir    Directory used to clone the repository
Default: .work/bluecat_change_requests

--outdir     Directory where output files will be written
Default: out

Behavior:
The script compares the HEAD commit with a BASE commit and analyzes
the detected file changes.

Governance rules apply ONLY to files under the `requests/` directory.

Allowed:
- Added YAML files (.yml or .yaml)
- Modified YAML files (.yml or .yaml)
- Deleted files under requests/ (currently allowed but ignored)

Violations:
- Any rename operation involving files under `requests/`
- Any file added or modified under `requests/` that is NOT .yml/.yaml
- Any unexpected Git change type under `requests/`

Outputs:
request_files.txt
List of request YAML files detected in the change set.
(files under requests/ that are Added or Modified).

governance_report.md
Markdown report containing:
- repository information
- resolved commit SHAs
- detected changes
- governance violations
- summary of results

Exit Codes:
0   Governance checks passed
2   Invalid arguments or usage error
3   Governance violations detected
EOF
}

REPO_URL=""
HEAD_REF=""
BASE_REF=""
WORKDIR=".work/bluecat_change_requests"
OUTDIR="out"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="${2:-}"; shift 2 ;;
    --head)     HEAD_REF="${2:-}"; shift 2 ;;
    --base)     BASE_REF="${2:-}"; shift 2 ;;
    --workdir)  WORKDIR="${2:-}"; shift 2 ;;
    --outdir)   OUTDIR="${2:-}"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

if [[ -z "$REPO_URL" || -z "$HEAD_REF" ]]; then
  echo "ERROR: --repo-url and --head are required."
  usage
  exit 2
fi

mkdir -p "$OUTDIR"
mkdir -p "$(dirname "$WORKDIR")"

REQ_FILES_TXT="$OUTDIR/request_files.txt"
REPORT_MD="$OUTDIR/governance_report.md"

# Clean previous outputs
: > "$REQ_FILES_TXT"
: > "$REPORT_MD"

echo "# Governance Report" >> "$REPORT_MD"
echo "" >> "$REPORT_MD"
echo "- Repo URL: \`$REPO_URL\`" >> "$REPORT_MD"
echo "- Head ref: \`$HEAD_REF\`" >> "$REPORT_MD"
echo "- Base ref: \`${BASE_REF:-auto}\`" >> "$REPORT_MD"
echo "" >> "$REPORT_MD"

# Fresh clone each run (MVP deterministic)
rm -rf "$WORKDIR"
git clone --quiet "$REPO_URL" "$WORKDIR"

pushd "$WORKDIR" >/dev/null
git fetch --quiet --all --tags
git checkout --quiet "$HEAD_REF"

# If a previous commit exists, then use it as BASE_REF
# Otherwise, leave BASE_REF empty, this handles repos with one commit.
# Determine base if not provided
if [[ -z "$BASE_REF" ]]; then
  if git rev-parse --verify --quiet HEAD~1 >/dev/null; then
    BASE_REF="HEAD~1"
  else
    BASE_REF=""
  fi
fi

# This converts HEAD into the full commit hash
HEAD_SHA="$(git rev-parse HEAD)"

# if variable is NOT empty, then create a git diff range
# so that changes can be detected with base_commit..current_commit
# if no base exists, only show files from the first commit.
if [[ -n "$BASE_REF" ]]; then
  BASE_SHA="$(git rev-parse "$BASE_REF")"
  DIFF_RANGE="$BASE_SHA..$HEAD_SHA"
else
  DIFF_RANGE="$HEAD_SHA"
fi

# Compute absolute clone dir (for absolute request file paths)
CLONE_ABS_DIR="$(pwd -P)"
popd >/dev/null

echo "- Resolved head SHA: \`$HEAD_SHA\`" >> "$REPORT_MD"
if [[ -n "$BASE_REF" ]]; then
  echo "- Resolved base SHA: \`$BASE_SHA\`" >> "$REPORT_MD"
else
  echo "- Resolved base SHA: \`(empty tree)\`" >> "$REPORT_MD"
fi
echo "- Clone dir: \`$CLONE_ABS_DIR\`" >> "$REPORT_MD"
echo "" >> "$REPORT_MD"

# Get name-status diff (run inside clone)
pushd "$WORKDIR" >/dev/null

# Git diff terms
# M means modified
# A means added
# D means deleted
if [[ -n "$BASE_REF" ]]; then
  mapfile -t CHANGES < <(git diff --name-status "$DIFF_RANGE")
else
  mapfile -t CHANGES < <(git diff-tree --no-commit-id --name-status -r "$HEAD_SHA")
fi
popd >/dev/null

violations=0
processed_count=0

echo "## Detected changes" >> "$REPORT_MD"
echo "" >> "$REPORT_MD"

if [[ ${#CHANGES[@]} -eq 0 ]]; then
  echo "- (no changes detected)" >> "$REPORT_MD"
else
  for line in "${CHANGES[@]}"; do
    status="$(awk '{print $1}' <<<"$line")"

    if [[ "$status" == R* ]]; then
      old_path="$(awk '{print $2}' <<<"$line")"
      new_path="$(awk '{print $3}' <<<"$line")"
      echo "- \`$status\` $old_path -> $new_path" >> "$REPORT_MD"

      if [[ "$old_path" == requests/* || "$new_path" == requests/* ]]; then
        echo "  - Violation: renames under requests/ are not allowed." >> "$REPORT_MD"
        ((violations+=1))
      fi
      continue
    fi

    path="$(awk '{print $2}' <<<"$line")"
    echo "- \`$status\` $path" >> "$REPORT_MD"

    if [[ "$path" == requests/* ]]; then
      case "$status" in
        A|M)
          if [[ "$path" =~ \.ya?ml$ ]]; then
            echo "$path" >> "$REQ_FILES_TXT"
            ((processed_count+=1))
          else
            echo "  - Violation: only .yml/.yaml files are allowed under requests/." >> "$REPORT_MD"
            ((violations+=1))
          fi
          ;;
        D)
          echo "  - Allowed (MVP): deletion under requests/ (ignored by validation)." >> "$REPORT_MD"
          ;;
        *)
          echo "  - Violation: unexpected change type '$status' under requests/." >> "$REPORT_MD"
          ((violations+=1))
          ;;
      esac
    fi
  done
fi

echo "" >> "$REPORT_MD"
echo "## Summary" >> "$REPORT_MD"
echo "" >> "$REPORT_MD"
echo "- Added request YAML files: \`$processed_count\`" >> "$REPORT_MD"
echo "- Governance violations: \`$violations\`" >> "$REPORT_MD"
echo "" >> "$REPORT_MD"

if [[ "$processed_count" -eq 0 ]]; then
  echo "- No new request files detected under requests/." >> "$REPORT_MD"
fi

if [[ "$violations" -gt 0 ]]; then
  echo "" >> "$REPORT_MD"
  echo "Governance checks failed." >> "$REPORT_MD"
  exit 3
fi

echo "Governance checks passed." >> "$REPORT_MD"
exit 0
