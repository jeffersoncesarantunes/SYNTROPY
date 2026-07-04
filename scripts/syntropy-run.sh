#!/usr/bin/env bash
set -euo pipefail

SYNTROPY_DIR="$( (cd "$(dirname "$0")/.." && pwd 2>/dev/null) || pwd)"
CASE_ID="FOR-$(date +%Y%m%d-%H%M%S)"
CASE_ROOT="/tmp/syntropy/$CASE_ID"
YARA_RULE=""

LINSPEC_BIN=$(command -v linspec 2>/dev/null || echo "$SYNTROPY_DIR/LinSpec/linspec")
KSCANNER_BIN=$(command -v kscanner 2>/dev/null || echo "$SYNTROPY_DIR/K-Scanner/kscanner")
SIREN_DIR="${SIREN_DIR:-$SYNTROPY_DIR/S.I.R.E.N}"
SCRIPTS_DIR="${SCRIPTS_DIR:-$SYNTROPY_DIR/scripts}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yara) YARA_RULE="$2"; shift 2 ;;
        --out) CASE_ROOT="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 [--yara <rules.yara>] [--out <dir>]"
            exit 0
            ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

validate_path() {
    local path=$1
    if [[ -n "$path" && "$path" != /tmp/syntropy/* && "$path" != /* ]]; then
        echo "Error: --out must be an absolute path" >&2
        exit 1
    fi
}
validate_path "$CASE_ROOT"

validate_yara_rule() {
    local rule=$1
    if [[ -n "$rule" && ! -f "$rule" ]]; then
        echo "Error: YARA rule file not found: $rule" >&2
        exit 1
    fi
}
validate_yara_rule "$YARA_RULE"

mkdir -p "$CASE_ROOT"/{audit,acquire,analyze}

printf "\033[36m[SYNTROPY]\033[0m Case: %s\n" "$CASE_ID"
printf "\033[36m[SYNTROPY]\033[0m Output: %s\n" "$CASE_ROOT"

printf "\033[36m[1/5]\033[0m LinSpec -- Kernel Hardening Audit...\n"
cd "$(dirname "$LINSPEC_BIN")"
sudo "$LINSPEC_BIN" 2>/dev/null || true
for f in reports/report.json reports/report.csv; do
    [[ -f "$f" ]] && cp "$f" "$CASE_ROOT/audit/" 2>/dev/null || true
done
printf "\033[32m       ->\033[0m %s/audit/report.json\n" "$CASE_ROOT"

printf "\033[36m[2/5]\033[0m S.I.R.E.N -- Memory Acquisition (kcore)...\n"
cd "$SIREN_DIR"
mkdir -p dumps/binaries dumps/reports dumps/checksums
sudo bash src/siren.sh --full 2>/dev/null || true

LATEST_DUMP=$(find dumps/binaries -maxdepth 1 -name '*.bin' -type f 2>/dev/null | sort -r | head -1)
if [[ -n "$LATEST_DUMP" ]]; then
    cp "$LATEST_DUMP" "$CASE_ROOT/acquire/"
    cp dumps/reports/*.json "$CASE_ROOT/acquire/" 2>/dev/null || true
    cp dumps/checksums/*.sha256 "$CASE_ROOT/acquire/" 2>/dev/null || true
    cp dumps/binaries/*.txt "$CASE_ROOT/acquire/" 2>/dev/null || true
    cp dumps/reports/manifest.csv "$CASE_ROOT/acquire/" 2>/dev/null || true
    cp dumps/binaries/*.meta.json "$CASE_ROOT/acquire/" 2>/dev/null || true
    DUMP_HASH=$(sha256sum "$LATEST_DUMP" | awk '{print $1}')
    printf "\033[32m       ->\033[0m %s (%s)\n" "$(basename "$LATEST_DUMP")" "$(du -h "$LATEST_DUMP" | cut -f1)"
    printf "\033[32m       ->\033[0m SHA256: %s\n" "$DUMP_HASH"
else
    DUMP_HASH="none"
    printf "\033[33m       ->\033[0m No dump found (run SIREN manually if needed)\n"
fi

printf "\033[36m[3/5]\033[0m K-Scanner -- Live RWX Analysis...\n"
cd "$(dirname "$KSCANNER_BIN")"
EXTRA_ARGS=(--silent-jit)
[[ -n "$YARA_RULE" ]] && EXTRA_ARGS+=(--yara "$YARA_RULE")
sudo "$KSCANNER_BIN" --json "${EXTRA_ARGS[@]}" 2>/dev/null | tee "$CASE_ROOT/analyze/kscan_results.json" > /dev/null || true
ALERTS=$(grep -c '"RWX ALERT"' "$CASE_ROOT/analyze/kscan_results.json" 2>/dev/null || echo 0)
printf "\033[32m       ->\033[0m %s alerts, saved to analyze/kscan_results.json\n" "$ALERTS"

printf "\033[36m[4/5]\033[0m Generating Unified Report...\n"
bash "$SCRIPTS_DIR/syntropy-bind.sh" "$CASE_ROOT" "$DUMP_HASH"

printf "\033[36m[5/5]\033[0m Generating Remediation Suggestions...\n"
bash "$SCRIPTS_DIR/syntropy-remediate.sh" "$CASE_ROOT" 2>/dev/null || true

printf "\n\033[32m[SYNTROPY] Done.\033[0m\n"
printf "  Case:  \033[36m%s\033[0m\n" "$CASE_ID"
printf "  Root:  %s\n" "$CASE_ROOT"
printf "  Report: %s/syntropy_report.json\n" "$CASE_ROOT"
printf "  Remediation: %s/remediation_plan.json\n" "$CASE_ROOT"
