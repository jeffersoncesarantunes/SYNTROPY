# ● Acquisition Model

This document describes the internal logic used by S.I.R.E.N to safely acquire physical memory from a live Linux system, featuring adaptive selection through audit synchronization.

---

## 1. Data Sources

S.I.R.E.N relies on kernel-exposed interfaces:

- `/proc/iomem` → memory map classification and leak detection.
- `/dev/mem` → partial raw physical memory access (legacy/restricted).
- `/proc/kcore` → dynamic ELF-formatted full memory acquisition interface.

---

## 2. Audit-Aware Classification

The tool integrates with **LinSpec** findings to determine the optimal acquisition path:

1. **System RAM Mapping:** Parses `/proc/iomem` to identify regions labeled as `System RAM`.
2. **Integrity Pre-check:** Validates if the kernel is returning actual data or NULL bytes (0x00) due to active lockdowns.
3. **Audit Sync:** Automatically adjusts acquisition logic based on `report.json` data (e.g., detecting `kptr_restrict` or `Kernel Lockdown`).

---

## 3. Acquisition Modes

### a) Adaptive Controlled Extraction (`/dev/mem`)
- Targeted extraction based on mapped safe ranges.
- Automatically bypassed if audit reports strict hardware lockdowns.
- Requires `iomem=relaxed` for access to non-standard ranges.

### b) Full Forensic Extraction (`/proc/kcore`)
- High-fidelity acquisition via kernel memory mapping.
- Preferred fallback when `/dev/mem` is restricted by `CONFIG_STRICT_DEVMEM`.
- Supports large-scale dumps for comprehensive analysis.

---

## 4. Acquisition Workflow

The process follows a modular pipeline:

1. **Audit Stage:** Loads LinSpec artifacts to evaluate kernel vulnerability status.
2. **Mapping Stage:** Identifies valid physical addresses from `/proc/iomem`.
3. **Extraction Stage:** Data is read from the prioritized source and written to a `.bin` dump.
4. **Validation Stage:** Performs real-time NULL-byte detection and SHA256 integrity hashing.
5. **Post-Processing:** Automated string extraction and forensic JSON/CSV report generation.

---

## 5. Kernel Protections & Bypasses

Modern Linux systems may enforce strict barriers:

- **STRICT_DEVMEM:** Limits access to physical memory. S.I.R.E.N attempts a `/proc/kcore` fallback or suggests `iomem=relaxed`.
- **Kernel Lockdown:** May prevent full memory reads.
- **NULL-Byte Padding:** Some kernels return zeroed pages to protect sensitive regions. S.I.R.E.N detects this during acquisition to avoid "phantom" dumps.

---

## 6. Operational Constraints

- **Root Access:** MANDATORY for interacting with kernel memory interfaces.
- **System Stability:** Accessing certain reserved hardware regions may cause system hangs. Users should utilize the "Ignore" option (Option 3) for restricted ranges.
- **Resource Aware:** Validates available disk space before initiating large-scale dumps.

---

*This model prioritizes adaptive safety, forensic traceability, and cross-tool symbiosis.*
