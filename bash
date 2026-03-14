#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  discover_requests.sh --repo-url <url> --head <ref> [--base <ref>] [--workdir <dir>] [--outdir <dir>]

Args:
  --repo-url   Git URL of bluecat_change_requests repo (required)
  --head       Commit SHA or ref to evaluate as "new state" (required)
  --base       Commit SHA or ref to compare against (optional; default: <head>~1)
  --workdir    Working directory for clone (optional; default: .work/bluecat_change_requests)
  --outdir     Output dir (optional; default: out)

Behavior:
  - Only allows ADDED files under requests/ with .yml/.yaml extension.
  - Fails if any file under requests/ is Modified/Deleted/Renamed,
    or if any non-yaml file is added under requests/.
Outputs:
  - out/request_files.txt (ABSOLUTE paths)
  - out/governance_report.md
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
