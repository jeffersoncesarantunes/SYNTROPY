#!/usr/bin/env bash
set -euo pipefail

export CASE_ROOT="${1:-.}"
export DUMP_HASH="${2:-unknown}"

exec python3 -c "
import json, os, glob, sys

root = os.environ['CASE_ROOT']
dump_hash = os.environ['DUMP_HASH']

audit = {}
audit_path = os.path.join(root, 'audit', 'report.json')
if os.path.exists(audit_path):
    with open(audit_path) as f:
        audit = json.load(f)

acquire = {}
acquire_reports = glob.glob(os.path.join(root, 'acquire', 'report_*.json'))
if acquire_reports:
    with open(acquire_reports[0]) as f:
        acquire = json.load(f)

kscan = []
kscan_path = os.path.join(root, 'analyze', 'kscan_results.json')
if os.path.exists(kscan_path):
    try:
        with open(kscan_path) as f:
            kscan = json.load(f)
    except json.JSONDecodeError:
        pass

report = {
    'case_id': os.path.basename(root),
    'syntropy_version': '1.0',
    'phases': {
        'audit': audit,
        'acquisition': acquire,
        'analysis': {
            'tool': 'K-Scanner',
            'alerts_total': sum(1 for p in kscan if p.get('status') == 'RWX ALERT'),
            'processes': kscan
        }
    },
    'chain_of_custody': {
        'acquisition_hash': dump_hash,
        'artifacts': {
            'audit': 'audit/report.json',
            'acquisition': 'acquire/',
            'analysis': 'analyze/kscan_results.json'
        }
    }
}

out = os.path.join(root, 'syntropy_report.json')
with open(out, 'w') as f:
    json.dump(report, f, indent=2)

print('       -> {}'.format(out))
print('       -> {} alerts, {} processes'.format(
    report['phases']['analysis']['alerts_total'],
    len(report['phases']['analysis']['processes'])
))
"
