# ● Safety Model

This document defines the operational safety principles of S.I.R.E.N.

---

## 1. Read-Only Operation

S.I.R.E.N performs:

- No writes to system memory
- No kernel modifications
- No process interference

All operations are passive.

---

## 2. Controlled Memory Access

Access is performed via:

- `/dev/mem` (restricted access)
- `/proc/kcore` (alternative interface)

When using `/dev/mem`:

- Only valid System RAM regions are targeted
- Unsafe regions are avoided

---

## 3. System Stability

To prevent system instability:

- Memory regions are validated before access
- Disk space is checked before acquisition
- Kernel restrictions are respected

---

## 4. User Confirmation

Certain operations require explicit user interaction:

- Direct memory extraction
- Full memory acquisition

This ensures:

- User awareness
- Explicit consent before risk

---

## 5. Failure Handling

If access is denied:

- Operation stops gracefully
- No forced reads are attempted

---

## 6. Forensic Integrity

The tool ensures:

- SHA256 hashing after acquisition
- Structured JSON reporting
- Persistent CSV logging (manifest)

---

*Safety and evidence integrity are prioritized over completeness.*

