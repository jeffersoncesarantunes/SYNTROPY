# ● Safety Model

This document defines the operational safety principles of S.I.R.E.N, focusing on system stability and data integrity during high-stakes forensic acquisition.

---

## 1. Passive Read-Only Operation

S.I.R.E.N is strictly non-intrusive:

- **No Memory Modification:** Zero writes to system RAM.
- **No Kernel Hooks:** Operates without loading modules or modifying kernel structures.
- **Passive Triage:** Interacts only with standard kernel interfaces (/dev/mem, /proc/kcore).

---

## 2. Intelligence-Driven Access

To minimize risks, S.I.R.E.N utilizes an "Audit First" approach:

- **LinSpec Integration:** Synchronizes with kernel audit reports to identify lockdowns before attempting access.
- **Region Validation:** Only "System RAM" labels from /proc/iomem are targeted by default.
- **NULL-Byte Detection:** Real-time entropy monitoring identifies if the kernel is serving "phantom data" to protect itself.

---

## 3. System Stability Protocols

Memory acquisition, especially on modern hardware, carries the risk of system hangs. S.I.R.E.N mitigates this through:

- **Range Gating:** Explicitly avoids reserved or hardware-mapped memory regions.
- **Resource Management:** Performs disk space pre-checks to prevent system-wide I/O failure during 16GB+ dumps.
- **The "Ignore" Strategy:** In case of restricted access, users are encouraged to skip (Option 3) to prevent kernel panics.

---

## 4. Operational Guardrails (Action Required)

Sensitive operations trigger an explicit decision-making menu:

- **Explicit Consent:** No large-scale acquisition begins without user confirmation.
- **Risk Assessment:** The "ACTION REQUIRED" prompt informs the user about restricted ranges, allowing for manual intervention (Attempt/Bypass/Ignore).

---

## 5. Failure & Exception Handling

If access to a memory range is denied or restricted by CONFIG_STRICT_DEVMEM:

- **Graceful Degradation:** The tool stops current range processing without crashing the entire scan.
- **Fallback Logic:** Automatically suggests /proc/kcore if /dev/mem is blocked.
- **No Forced Reads:** S.I.R.E.N never attempts to force access to locked registers.

---

## 6. Forensic Evidence Integrity

Safety extends to the data itself:

- **Post-Acquisition Hashing:** Automatic SHA256 generation for every binary dump.
- **Environmental Context:** Captures the system state in manifest.csv and report.json.
- **Post-Analysis Readiness:** Ensures strings and hashes are extracted immediately to preserve volatile context.

---

*Safety and system stability are prioritized over raw data completeness.*
