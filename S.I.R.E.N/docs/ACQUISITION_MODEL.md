# ● Acquisition Model

This document describes the internal logic used by S.I.R.E.N to safely acquire physical memory from a live Linux system.

---

## 1. Data Sources

S.I.R.E.N relies on kernel-exposed interfaces:

- `/proc/iomem` → memory map classification
- `/dev/mem` → partial raw physical memory access
- `/proc/kcore` → full memory acquisition interface

---

## 2. Memory Classification

The tool parses `/proc/iomem` to identify memory regions labeled as:

- System RAM (safe for acquisition)
- Reserved / Hardware-mapped regions (unsafe)

Only **System RAM** ranges are selected when using `/dev/mem`.

---

## 3. Acquisition Modes

S.I.R.E.N supports two acquisition strategies:

### a) Controlled Extraction (`/dev/mem`)

- Limited memory extraction (default capped size)
- Used for safe testing and validation
- May be restricted by kernel protections

### b) Full Memory Extraction (`/proc/kcore`)

- Reads memory based on total physical RAM size
- Used when `/dev/mem` is restricted
- Produces large-scale dumps

---

## 4. Acquisition Workflow

The acquisition process follows:

1. Data is read from the selected source
2. Raw memory is written to a dump file
3. SHA256 hash is generated
4. Strings are extracted for analysis
5. JSON report and CSV manifest are created

---

## 5. Kernel Restrictions

Modern Linux systems may enforce:

- `CONFIG_STRICT_DEVMEM`

When enabled:

- `/dev/mem` access is limited
- Full acquisition may require `/proc/kcore`

---

## 6. Limitations

- Requires root privileges
- `/dev/mem` may be restricted
- `/proc/kcore` output may include kernel abstractions
- Not a replacement for dedicated forensic frameworks (e.g., LiME)

---

*This model prioritizes safety, traceability, and controlled acquisition.*

