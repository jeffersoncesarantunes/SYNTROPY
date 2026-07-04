#!/usr/bin/env bash
set -euo pipefail

SYNTROPY_DIR="$( (cd "$(dirname "$0")/.." && pwd 2>/dev/null) || pwd)"
REMEDIATOR_BIN=$(command -v remediator 2>/dev/null || echo "$SYNTROPY_DIR/LinSpec/remediator")

CASE_ROOT="${1:-}"
FLAG_APPLY=0
FLAG_FORCE=0

usage() {
    echo "Usage: $0 <case-root> [--apply] [--force]"
    echo ""
    echo "Reads a completed SYNTROPY case directory and generates"
    echo "a structured remediation plan (remediation_plan.json)"
    echo ""
    echo "Options:"
    echo "  --apply    Apply remediations interactively"
    echo "  --force    Skip confirmation prompts with --apply"
    echo ""
    echo "If <case-root> is omitted, the latest /tmp/syntropy/FOR-* is used."
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --help|-h) usage ;;
    esac
done

for arg in "$@"; do
    case "$arg" in
        --apply) FLAG_APPLY=1 ;;
        --force) FLAG_FORCE=1 ;;
        --help|-h) ;;
        *)
            if [[ -z "$CASE_ROOT" ]]; then
                CASE_ROOT="$arg"
            fi
            ;;
    esac
done

if [[ -z "$CASE_ROOT" ]]; then
    LATEST=$(find /tmp/syntropy -maxdepth 1 -type d -name 'FOR-*' 2>/dev/null | sort -r | head -1)
    if [[ -z "$LATEST" ]]; then
        echo "Error: no case-root provided and no /tmp/syntropy/FOR-* found."
        exit 1
    fi
    CASE_ROOT="$LATEST"
fi

if [[ ! -d "$CASE_ROOT" ]]; then
    echo "Error: case directory not found: $CASE_ROOT"
    exit 1
fi

CASE_ID="$(basename "$CASE_ROOT")"
AUDIT_DIR="$CASE_ROOT/audit"
ACQUIRE_DIR="$CASE_ROOT/acquire"
ANALYZE_DIR="$CASE_ROOT/analyze"
TMPDIR="$CASE_ROOT/.remediate_tmp"

RC=0

LINSPEC_REPORT="$AUDIT_DIR/report.json"
KSCAN_RESULTS="$ANALYZE_DIR/kscan_results.json"

printf "\033[36m[SYNTROPY REMEDIATE]\033[0m Case: %s\n" "$CASE_ID"
printf "\033[36m[SYNTROPY REMEDIATE]\033[0m Root:  %s\n" "$CASE_ROOT"

mkdir -p "$TMPDIR"

linspec_phase() {
    printf "\033[36m[1/4]\033[0m LinSpec -- Kernel Hardening Remediations...\n"

    if [[ ! -f "$LINSPEC_REPORT" ]]; then
        printf "\033[33m       -> No LinSpec report found at %s\033[0m\n" "$LINSPEC_REPORT"
        echo "[]" > "$TMPDIR/remediations_linspec.json"
        echo "" > "$TMPDIR/sysctl_block.txt"
        return
    fi

    if [[ -x "$REMEDIATOR_BIN" ]]; then
        local rem_out="$CASE_ROOT/remediation_linspec.json"
        if [[ "$FLAG_APPLY" -eq 1 ]]; then
            if [[ "$FLAG_FORCE" -eq 1 ]]; then
                sudo "$REMEDIATOR_BIN" -i "$LINSPEC_REPORT" -o "$rem_out" --apply --force || true
            else
                sudo "$REMEDIATOR_BIN" -i "$LINSPEC_REPORT" -o "$rem_out" --apply || true
            fi
        else
            "$REMEDIATOR_BIN" -i "$LINSPEC_REPORT" -o "$rem_out" 2>/dev/null || true
        fi

        if [[ -f "$rem_out" ]]; then
            python3 -c "
import json
with open('$rem_out') as f:
    d = json.load(f)
with open('$TMPDIR/remediations_linspec.json', 'w') as o:
    json.dump(d.get('remediations', []), o)
with open('$TMPDIR/sysctl_block.txt', 'w') as o:
    o.write(d.get('persistent_block', ''))
" 2>/dev/null || echo "[]" > "$TMPDIR/remediations_linspec.json"
            printf "\033[32m       ->\033[0m %s/remediation_linspec.json\n" "$CASE_ROOT"
        else
            echo "[]" > "$TMPDIR/remediations_linspec.json"
            echo "" > "$TMPDIR/sysctl_block.txt"
        fi
    else
        printf "\033[33m       -> remediator not found, using Python fallback\033[0m\n"
        python3 -c "
import json
try:
    with open('$LINSPEC_REPORT') as f:
        data = json.load(f)
    out = []
    for c in data.get('checks', []):
        if c.get('remediable') and c.get('result') in ('vuln', 'warn'):
            out.append({
                'id': c.get('id'),
                'check': c.get('name', ''),
                'severity': 'critical' if c.get('result') == 'vuln' else 'warning',
                'current': c.get('current', 0),
                'recommended': c.get('remediate_val', c.get('expected', 0)),
                'source': 'linspec',
                'automated': True
            })
    with open('$TMPDIR/remediations_linspec.json', 'w') as o:
        json.dump(out, o)
except Exception:
    with open('$TMPDIR/remediations_linspec.json', 'w') as o:
        json.dump([], o)
" 2>/dev/null || echo "[]" > "$TMPDIR/remediations_linspec.json"
        echo "" > "$TMPDIR/sysctl_block.txt"
    fi
}

kscanner_phase() {
    printf "\033[36m[2/4]\033[0m K-Scanner -- Process Remediations...\n"

    if [[ ! -f "$KSCAN_RESULTS" ]]; then
        printf "\033[33m       -> No K-Scanner results at %s\033[0m\n" "$KSCAN_RESULTS"
        echo "[]" > "$TMPDIR/remediations_kscan.json"
        return
    fi

    python3 -c "
import json
try:
    with open('$KSCAN_RESULTS') as f:
        procs = json.load(f)
    out = []
    if not isinstance(procs, list):
        procs = [procs]
    for p in procs:
        if p.get('status') == 'RWX ALERT':
            pid = p.get('pid', 0)
            pname = p.get('process', 'unknown')
            conf = p.get('confidence', 'MEDIUM')
            ctn = p.get('container', '')
            sev = 'critical' if conf == 'CRITICAL' else ('warning' if conf in ('MEDIUM', 'SUSPICIOUS') else 'info')
            cmd = 'kill -9 %d' % pid
            alt = ''
            if ctn:
                alt = 'docker stop %s' % ctn
            out.append({
                'source': 'kscanner',
                'type': 'process_rwx',
                'severity': sev,
                'pid': pid,
                'process': pname,
                'container': ctn,
                'command': cmd,
                'alternative': alt,
                'confidence': conf,
                'automated': True
            })
    with open('$TMPDIR/remediations_kscan.json', 'w') as o:
        json.dump(out, o)
except Exception:
    with open('$TMPDIR/remediations_kscan.json', 'w') as o:
        json.dump([], o)
" 2>/dev/null || echo "[]" > "$TMPDIR/remediations_kscan.json"

    local count
    count=$(python3 -c "import json; d=json.load(open('$TMPDIR/remediations_kscan.json')); print(len(d))" 2>/dev/null || echo 0)
    printf "\033[32m       ->\033[0m %s process remediations generated\n" "$count"
}

siren_phase() {
    printf "\033[36m[3/4]\033[0m S.I.R.E.N -- Acquisition Remediations...\n"

    local dumps_dir="$ACQUIRE_DIR"
    local integrity_issues=0

    for sf in "$dumps_dir"/*.sha256; do
        [[ -f "$sf" ]] || continue
        local bin="${sf%.sha256}"
        if [[ -f "$bin" ]]; then
            if ! sha256sum -c "$sf" >/dev/null 2>&1; then
                integrity_issues=$((integrity_issues + 1))
            fi
        fi
    done

    python3 -c "
import json, os
out = []
dumps_dir = '$dumps_dir'
integrity_issues = $integrity_issues

if integrity_issues > 0:
    out.append({
        'source': 'siren',
        'type': 'integrity_failure',
        'severity': 'critical',
        'description': '%d dump(s) failed SHA256 verification' % integrity_issues,
        'command': 'investigate %s' % dumps_dir,
        'automated': False
    })

dumps = [f for f in os.listdir(dumps_dir) if f.endswith('.bin') and os.path.isfile(os.path.join(dumps_dir, f))]
if len(dumps) == 0:
    out.append({
        'source': 'siren',
        'type': 'missing_acquisition',
        'severity': 'warning',
        'description': 'No memory dump acquired -- acquisition was skipped or failed',
        'command': 'sudo ./S.I.R.E.N/src/siren.sh --full',
        'automated': False
    })

with open('$TMPDIR/remediations_siren.json', 'w') as o:
    json.dump(out, o)
" 2>/dev/null || echo "[]" > "$TMPDIR/remediations_siren.json"

    local scount
    scount=$(python3 -c "import json; d=json.load(open('$TMPDIR/remediations_siren.json')); print(len(d))" 2>/dev/null || echo 0)
    printf "\033[32m       ->\033[0m %s acquisition remediations\n" "$scount"
}

merge_phase() {
    printf "\033[36m[4/4]\033[0m Merging Remediation Plan...\n"

    local plan_path="$CASE_ROOT/remediation_plan.json"

    python3 -c "
import json

with open('$TMPDIR/remediations_linspec.json') as f:
    linspec = json.load(f)
with open('$TMPDIR/remediations_kscan.json') as f:
    kscan = json.load(f)
with open('$TMPDIR/remediations_siren.json') as f:
    siren = json.load(f)
with open('$TMPDIR/sysctl_block.txt') as f:
    sysctl_block = f.read()

all_items = linspec + kscan + siren

critical = sum(1 for r in all_items if r.get('severity') == 'critical')
warning  = sum(1 for r in all_items if r.get('severity') == 'warning')
info     = sum(1 for r in all_items if r.get('severity') == 'info')

persistent_lines = []
for r in linspec:
    c = r.get('check', '')
    v = r.get('recommended', 0)
    if c and v:
        persistent_lines.append('%s = %d' % (c, v))

persistent_block = '# SYNTROPY Remediation Plan\n'
persistent_block += '# Case: $CASE_ID\n'
persistent_block += '# Add to /etc/sysctl.d/99-syntropy-hardening.conf\n#\n'
for line in persistent_lines:
    persistent_block += line + '\n'

plan = {
    'case_id': '$CASE_ID',
    'tool': 'SYNTROPY Remediation',
    'version': '1.0',
    'summary': {
        'total': len(all_items),
        'critical': critical,
        'warning': warning,
        'info': info
    },
    'remediations': all_items,
    'persistent_block': persistent_block
}

with open('$plan_path', 'w') as f:
    json.dump(plan, f, indent=2)

print('       -> %s' % '$plan_path')
print('       -> %d total (%d critical, %d warning, %d info)' % (
    len(all_items), critical, warning, info))
" 2>/dev/null || {
        printf "\033[31m[!] Failed to merge remediation plan\033[0m\n"
        RC=1
    }

    rm -rf "$TMPDIR"
}

apply_phase() {
    if [[ "$FLAG_APPLY" -eq 0 ]]; then
        return
    fi

    local plan_path="$CASE_ROOT/remediation_plan.json"
    if [[ ! -f "$plan_path" ]]; then
        printf "\033[31m[!] No remediation plan at %s\033[0m\n" "$plan_path"
        RC=1
        return
    fi

    printf "\n\033[36m[SYNTROPY REMEDIATE --apply]\033[0m\n"

    local total critical warning
    eval "$(python3 -c "
import json
with open('$plan_path') as f:
    p = json.load(f)
print('total=%d; critical=%d; warning=%d' % (p['summary']['total'], p['summary']['critical'], p['summary']['warning']))
" 2>/dev/null)"
    printf "  Plan: %s remediations (%s critical, %s warning)\n" "$total" "$critical" "$warning"

    if [[ "$FLAG_FORCE" -eq 0 ]]; then
        printf "\033[33m[?] Apply all automated remediations? [y/N]: \033[0m"
        read -r CONFIRM
        if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
            printf "\033[33m     Aborted.\033[0m\n"
            return
        fi
    fi

    if [[ -x "$REMEDIATOR_BIN" ]]; then
        printf "  Applying LinSpec sysctl remediations...\n"
        sudo "$REMEDIATOR_BIN" -i "$LINSPEC_REPORT" --apply --force 2>/dev/null || true
    fi

    python3 -c "
import json, subprocess, sys

with open('$plan_path') as f:
    plan = json.load(f)

applied = 0
skipped = 0

for r in plan['remediations']:
    if not r.get('automated', False):
        skipped += 1
        continue
    if r.get('source') == 'kscanner':
        cmd = r.get('command', '')
        if cmd:
            print('  [-] %s (PID %s)' % (r.get('process', '?'), r.get('pid', '?')))
            print('      Command: %s' % cmd)
            app = input('      Apply? [y/N]: ')
            if app.lower() == 'y':
                try:
                    subprocess.run(cmd.split(), check=False)
                    applied += 1
                except Exception as e:
                    print('      Failed: %s' % e)
                    skipped += 1
            else:
                skipped += 1

print()
print('  Applied: %d, Skipped: %d' % (applied, skipped))
" 2>/dev/null || true

    printf "\n  \033[33m[!] Persistent sysctl block saved to remediation_plan.json\033[0m\n"
    printf "      To persist across reboots, add to /etc/sysctl.d/99-syntropy-hardening.conf\n"
}

linspec_phase
kscanner_phase
siren_phase
merge_phase
apply_phase

printf "\n\033[32m[SYNTROPY REMEDIATE] Done.\033[0m\n"
printf "  Plan: %s/remediation_plan.json\n" "$CASE_ROOT"
exit $RC
