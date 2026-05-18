# ● Forensic Workflow

This document outlines the recommended workflow when using S.I.R.E.N in a forensic investigation.

---

## 1. Acquisition Phase

Run S.I.R.E.N and select the appropriate mode:

- `/dev/mem` → partial and controlled extraction
- `/proc/kcore` → full memory acquisition

Example:

    sudo ./src/siren.sh

---

## 2. Integrity Verification

After acquisition, verify data integrity:

    sha256sum -c dump_filename.sha256

This ensures the dump was not corrupted during extraction.

---

## 3. Artifact Extraction

Use the generated strings file:

    grep -Ei "pass|user|config" mem_dump.txt

This helps identify:

- Credentials
- Configuration data
- Indicators of compromise

---

## 4. Data Inspection

Perform low-level inspection:

    hexdump -C mem_dump.bin | head -n 20

This allows identification of:

- Memory patterns
- Embedded structures
- Suspicious payloads

---

## 5. Analysis Environment

For large dumps:

- Transfer files to a dedicated forensic workstation
- Avoid analyzing directly on the target system

---

## 6. Decision Making

Based on findings:

- Escalate investigation
- Isolate compromised system
- Preserve dump as forensic evidence

---

*This workflow is designed for controlled acquisition and rapid forensic triage.*
