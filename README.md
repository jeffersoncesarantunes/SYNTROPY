# 🐧 Linux Forensics Toolkit

### Live Memory Forensics · Kernel Hardening Audit · Malware Triage

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)]()
[![Language-C99](https://img.shields.io/badge/Core-C99-A8B9CC?style=flat-square&logo=c&logoColor=white)]()
[![Language-Bash](https://img.shields.io/badge/Acquisition-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)]()
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square)]()
[![Domain](https://img.shields.io/badge/Domain-Blue%20Team%20%7C%20DFIR-8A2BE2?style=flat-square)]()

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Components](#-components)
  - [LinSpec — Kernel Hardening Audit](#1-linspec--kernel-hardening-audit)
  - [S.I.R.E.N — Memory Acquisition](#2-siren--shell-interactive-runtime-entity-notifier)
  - [K-Scanner — Live Process Forensics](#3-k-scanner--live-process-forensics)
- [Integrated Architecture](#-integrated-architecture)
- [Incident Response Workflow](#-incident-response-workflow)
- [Quick Install](#-quick-install)
- [Detailed Usage Guide](#-detailed-usage-guide)
  - [Phase 1: LinSpec Audit](#phase-1-audit-with-linspec)
  - [Phase 2: S.I.R.E.N Acquisition](#phase-2-acquisition-with-siren)
  - [Phase 3: K-Scanner Analysis](#phase-3-analysis-with-k-scanner)
- [Post-Acquisition Analysis](#-post-acquisition-analysis)
- [Understanding Kernel "Option 3 (Ignore)"](#-understanding-kernel-option-3-ignore)
- [Troubleshooting](#-troubleshooting)
- [Case Study — Incident Simulation](#-case-study--incident-simulation)
- [Blue Team Portfolio](#-blue-team-portfolio)
- [Repository Structure](#-repository-structure)
- [License](#-license)

---

## ● Overview

The **Linux Forensics Toolkit** is an open-source forensic ecosystem composed of three specialized tools that work together to **audit, acquire, and analyze** volatile evidence on Linux systems under investigation.

Designed for **Blue Team / DFIR** professionals, the toolkit covers the full memory incident response lifecycle:

| Phase | Tool | Objective |
|-------|------|-----------|
| **1. Triage** | LinSpec | Audit kernel hardening posture and identify vulnerabilities |
| **2. Acquisition** | S.I.R.E.N | Extract memory dump with awareness of the active security profile |
| **3. Analysis** | K-Scanner | Detect processes with suspicious RWX memory regions in real-time |

**Key differentiators:**
- **Read-only operation** — no process injection, no kernel modification
- **Audit-aware acquisition** — adapts strategy based on active kernel protections
- **Cryptographic integrity** — SHA256 on every forensic artifact
- **Pure C99** (LinSpec, K-Scanner) and **Bash** (S.I.R.E.N) — zero external dependencies beyond system libraries

---

## ● Components

### 1. LinSpec — Kernel Hardening Audit

Audits critical Linux kernel security parameters in real-time, classifying each item as **PASS / WARN / VULN**.

**Audited areas:**

| Category | Parameters |
|----------|-----------|
| 🧠 Memory | ASLR, devmem_restrict |
| ⚙️ Kernel | kptr_restrict, dmesg_restrict, kexec_load_disabled |
| 🐛 CPU | Spectre v2, Meltdown |
| 🌐 Network | BPF JIT hardening, TCP syncookies, IP forwarding |
| 🔒 System | Ptrace scope, user namespaces, protected symlinks/hardlinks |

**Output:** Structured `report.json` + `report.csv`, consumed by S.I.R.E.N for adaptive acquisition decisions.

```bash
sudo ./linspec

# Sample output:
# [ 01 ]  MEMORY   >  ASLR                              [+] [   PASS   ]
# [ 02 ]  KERNEL   >  Kernel Pointer Restriction        [-] [   VULN   ]
# [ 12 ]  MEMORY   >  DMA Restriction                   [+] [   PASS   ]
# [ 15 ]  CPU      >  Meltdown Mitigation               [+] [   PASS   ]
```

---

### 2. S.I.R.E.N — Shell Interactive Runtime Entity Notifier

Volatile memory acquisition tool with contextual awareness. It reads LinSpec's `report.json` to automatically determine the best extraction strategy.

**Operation modes:**

| Option | Function | Source | Risk |
|--------|----------|--------|------|
| 1 | Map physical RAM | `/proc/iomem` | None |
| 2 | Verify pipeline | `/proc/version` | None |
| 3 | Live extraction | `/dev/mem` | ⚠️ Moderate (see Option 3) |
| 4 | Forensic bypass | `/proc/kcore` | Low |

**Audit-aware behavior:**
- If `kptr_restrict > 0` → Automatically switches to `/proc/kcore`
- If `spectre_v2 = 0` or `meltdown = 0` → Warns about side-channel leaks during extraction
- If `devmem_restrict = 1` → Prefers `/proc/kcore`

```bash
sudo ./src/siren.sh
```

---

### 3. K-Scanner — Live Process Forensics

Scans all active processes through `/proc/[PID]/maps` looking for memory regions with **RWX (Read-Write-Execute)** permissions — a direct violation of the **W^X (Write XOR Execute)** principle.

**Detects patterns including:**
- 🚨 `ANON_BLOB` — Anonymous executable region (shellcode, fileless malware)
- 🔥 `JIT_ENGINE` — JIT compilation (Firefox, Python, Node.js, Discord)
- 💣 `VOLATILE_FS` — RWX in `/tmp` or `/dev/shm`
- 📦 `PROC_STACK` — Executable stack (exploit or insecure configuration)

```bash
sudo ./kscanner --json > alerts.json
```

**Interactive TUI:** Navigate processes, view real-time alerts, press `ENTER` to extract suspicious regions with automatic SHA256, strings, and hexdump generation.

---

## ● Integrated Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    LINUX FORENSICS TOOLKIT                      │
├─────────────┬───────────────────┬───────────────────────────────┤
│   LinSpec   │     S.I.R.E.N     │          K-Scanner            │
│  (Auditor)  │  (Acquisitor)     │        (Analyzer)             │
├─────────────┼───────────────────┼───────────────────────────────┤
│ /proc/sys   │ /dev/mem          │ /proc/[PID]/maps              │
│ /sys/devices│ /proc/kcore       │ /proc/[PID]/mem               │
│             │ /proc/iomem       │                               │
├─────────────┼───────────────────┼───────────────────────────────┤
│      report.json ──────► audit-aware decision                   │
│             │                   │                               │
│             │   dumps/*.bin ◄───┘   RWX dump pipeline           │
│             │   dumps/*.sha256      │                           │
│             │   dumps/report_*.json │                           │
└─────────────┴───────────────────┴───────────────────────────────┘
```

**Data flow:**
1. **LinSpec** audits the kernel and produces `report.json`
2. **S.I.R.E.N** reads `report.json` → decides which memory interface to use → dumps memory
3. **K-Scanner** scans processes in real-time → flags RWX regions → extracts evidence if needed

---

## ● Incident Response Workflow

```
INCIDENT DETECTED
       │
       ▼
┌──────────────────┐
│ PHASE 1: TRIAGE  │
│ LinSpec          │  < 1 second
│ "Is the kernel   │
│  hardened?"      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ PHASE 2: ACQUIRE │
│ S.I.R.E.N        │  < 5 minutes
│ dump memory with │
│ integrity chain  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ PHASE 3: ANALYZE │
│ K-Scanner        │  < 30 seconds
│ "Who has RWX?"   │
│ + strings + hex  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ REPORT           │
│ Evidence with    │
│ cryptographic    │
│ chain of custody │
└──────────────────┘
```

---

## ● Quick Install

```bash
# Clone the unified toolkit
git clone https://github.com/your-user/Linux-Forensics-Toolkit.git
cd Linux-Forensics-Toolkit

# ---- LinSpec ----
cd LinSpec && make clean && make && cd ..

# ---- K-Scanner ----
cd K-Scanner && make clean && make && cd ..

# ---- SIREN ----
chmod +x SIREN/src/siren.sh

# Ready. Run as root:
sudo ./LinSpec/linspec
sudo ./SIREN/src/siren.sh
sudo ./K-Scanner/kscanner --help
```

**Prerequisites:** `gcc`, `make`, `ncurses`, `binutils`, `coreutils`, `bash 4.x+`, root privileges.

---

## ● Detailed Usage Guide

### Phase 1: Audit with LinSpec

```bash
cd LinSpec
sudo ./linspec
```

The report generated in `reports/report.json` is automatically consumed by S.I.R.E.N in the next phase.

**Flags to watch:**
- `kptr_restrict = 0` → Kernel pointers visible (information leak)
- `devmem_restrict = 0` → `/dev/mem` unrestricted (extraction risk)
- `spectre_v2 = 0` → CPU vulnerable to Spectre
- `bpf_jit_harden = 0` → BPF JIT without hardening

### Phase 2: Acquisition with S.I.R.E.N

```bash
cd SIREN
sudo ./src/siren.sh
```

Interactive menu:

```
1) Map Physical Memory (iomem)        → Lists valid RAM regions
2) Verify Extraction Pipeline         → Tests pipeline without extraction
3) Live Memory Extraction (/dev/mem)  → Extracts 100 MB via /dev/mem
4) Advanced Forensic Bypass (kcore)   → Extracts full RAM via /proc/kcore
5) Exit
```

**Production recommendation:** Option **4 (kcore)** — more stable, zero freeze risk.  
**Option 3 (/dev/mem):** Only if kcore is unavailable. See "Option 3 (Ignore)" section below.

### Phase 3: Analysis with K-Scanner

```bash
cd K-Scanner
sudo ./kscanner          # Interactive TUI mode
sudo ./kscanner --json   # JSON export (headless)
sudo ./kscanner --csv    # CSV export (headless)
```

**TUI controls:**
- ⬆⬇ Navigate processes
- **Red** rows = `RWX ALERT`
- **Green** rows = `SAFE`
- Press **ENTER** on a suspicious process → extracts RWX region
- Press **Q** to exit

**Live regex search across process memory:**
```bash
sudo ./kscanner --live <PID> "<regex>"
```

---

## ● Post-Acquisition Analysis

After extraction, the toolkit generates forensic artifacts in `K-Scanner/build/dumps/` or `SIREN/dumps/`. Here is how to analyze them:

### 1. Integrity Verification (SHA256)

```bash
# Verify all checksums
cd K-Scanner/build/dumps
sha256sum -c *.sha256

# For SIREN
cd SIREN/dumps/checksums
sha256sum -c *.sha256
```

### 2. String Extraction (Indicators of Compromise)

```bash
# Search for suspicious patterns in raw dump
strings dump.bin | grep -iE "(password|secret|token|ssh-rsa|BEGIN)"

# Search for URLs, IPs, domains
strings dump.bin | grep -E "(http|https|192\.168|10\.|172\.)"

# Search for known rootkit signatures
strings dump.bin | grep -iE "(diamorphine|suterusu|reptile|kbeast)"

# Extract long strings (≥ 10 chars) — useful for passwords and keys
strings -n 10 dump.bin | sort -u | head -50
```

### 3. Hexadecimal Inspection

```bash
# View dump header
hexdump -C dump.bin | head -30

# Search for specific hex patterns (e.g., NOP sled)
hexdump -C dump.bin | grep "90909090"

# Check if dump contains data or is null-filled
hexdump -C dump.bin | wc -l
```

### 4. Pre-Extracted Strings (K-Scanner)

K-Scanner automatically generates `*.strings.txt` and `*.hex.txt` during extraction:

```bash
# Rapid triage
grep -iE "http|cmd|bash|token|pass" *.strings.txt

# View hex preview
head -20 *.hex.txt
```

### 5. Structured Reports (S.I.R.E.N)

```bash
# View JSON report
cat dumps/reports/report_*.json | python3 -m json.tool

# View CSV manifest
column -s, -t < dumps/reports/manifest.csv
```

---

## ● Understanding Kernel "Option 3 (Ignore)"

### Why the system can freeze

On modern kernels (Arch Linux, Gentoo, Fedora), direct access to `/dev/mem` is monitored by `CONFIG_STRICT_DEVMEM`. When a tool attempts to read a memory address the kernel considers outside allowed user bounds, the **MMIO (Memory-Mapped I/O)** subsystem may trigger a **hardware lock** or generate a **Machine Check Exception (MCE)**.

### What happens in practice

```
Kernel: "Unauthorized access to reserved memory address.
         How should I proceed?"

Options:
  [1] Panic (halt the system immediately)
  [2] Reboot (forced restart)
  [3] Ignore (continue, skip the violation)      ← SELECT THIS
```

### The mechanism

When S.I.R.E.N uses `/dev/mem` (menu Option 3), the kernel presents this prompt before crashing. Selecting **"Ignore"** instructs the kernel to **not halt the operation** when encountering restricted pages, skipping problematic addresses and continuing extraction on valid regions.

### ⚠️ When to apply

| Scenario | Recommendation |
|----------|---------------|
| Production database server | ❌ Avoid `/dev/mem`. Use **Option 4 (kcore)** |
| Analysis workstation | ✅ `/dev/mem` with "Ignore" is acceptable |
| Kernel with `CONFIG_STRICT_DEVMEM` | ❌ `/dev/mem` will likely fail. Use kcore. |
| Kernel booted with `iomem=relaxed` | ✅ `/dev/mem` works without prompting |

### Safer alternative

For critical environments, Option **4 (Advanced Forensic Bypass — kcore)** accesses memory through `/proc/kcore`, a kernel-managed abstraction with no direct hardware I/O operations. This reduces freeze risk to practically zero.

---

## ● Troubleshooting

### 🔴 System froze during extraction

**Cause:** Access to a restricted memory region via `/dev/mem` without selecting "Ignore".
**Fix:** Reboot the server. Use `/proc/kcore` (Option 4) instead of `/dev/mem`.

### 🟡 Dump is too small or empty

**Cause:** `CONFIG_STRICT_DEVMEM` active, blocking the read.
**Fix:** Run LinSpec first to generate `report.json`. S.I.R.E.N will detect the restriction and automatically fall back to `/proc/kcore`.

### 🟡 "No valid data from /dev/mem"

**Cause:** `devmem_restrict = 1` in kernel.
**Fix:** Use Option 4 (kcore), or add `iomem=relaxed` to kernel boot parameters (requires reboot).

### 🟡 K-Scanner finds no processes

**Cause:** Running without root.
**Fix:** Always use `sudo ./kscanner`. `/proc/[PID]/maps` requires elevated privileges.

---

## ● Case Study — Incident Simulation

### Scenario

```
Company:  Medium-sized fintech
System:   Linux server (Arch Linux) running PostgreSQL 16
          — Production database with 2 TB of financial data
Event:    SOC team detects outbound connections from the DB server
          to an unauthorized external IP (185.xxx.xxx.xxx).
Hypothesis: Kernel rootkit or malware in a critical process.
Challenge: Collect evidence without taking the database down
            or interrupting operations.
```

### Action — Toolkit Deployment

#### Phase 1 — Triage with LinSpec (2 seconds)

```bash
sudo ./linspec
```

**Findings:**
```
[ 02 ]  KERNEL   >  kptr_restrict          [-] [ VULN ]   ← 0 (leaking)
[ 03 ]  SYSTEM   >  ptrace_scope           [+] [ PASS ]   ← 1 (restricted)
[ 04 ]  KERNEL   >  dmesg_restrict         [+] [ PASS ]   ← 1
[ 12 ]  MEMORY   >  devmem_restrict        [+] [ PASS ]   ← 1 (restricted)
[ 14 ]  CPU      >  Spectre v2             [-] [ VULN ]   ← Vulnerable
```

**Decision:** `devmem_restrict = 1` → `/dev/mem` blocked. Use `/proc/kcore`.

#### Phase 2 — Acquisition with S.I.R.E.N (4 minutes)

```bash
sudo ./src/siren.sh
# Option 4: Advanced Forensic Bypass (kcore)
```

S.I.R.E.N automatically reads `reports/report.json` from LinSpec:
- Detects `kptr_restrict = 0` → **Alert**: kernel pointers leaking
- Detects `devmem_restrict = 1` → **Decision**: use `/proc/kcore` (already Option 4's default)
- Extracts full 32 GB RAM dump → `dumps/full_scan_20260517.bin`
- Generates SHA256, CSV manifest, JSON report

**Manual equivalent:**
```bash
sha256sum full_scan_20260517.bin > checksums/full_scan_20260517.bin.sha256
strings full_scan_20260517.bin > dumps/binaries/full_scan_20260517.txt
```

#### Phase 3 — Analysis with K-Scanner (instant)

```bash
sudo ./kscanner --json
```

**Suspect lineup:**
```
PID     PROCESS           STATUS       MAP_ADDR
49363   Privileged Cont   RWX ALERT    36be10d13000   (10x JIT_ENGINE)
49488   WebExtensions     RWX ALERT    189906229000   (19x JIT_ENGINE)
53220   opencode          RWX ALERT    3ed35854000    (317x ANON_BLOB) ← ANOMALOUS
```

**Deep inspection of PID 53220:**

```bash
# Press ENTER on the process → automatic dump in build/dumps/
# Check extracted strings for IoCs
strings build/dumps/pid_53220_3ed35854000.bin | grep "185\."  # C2 IP confirmed
strings pid_53220_3ed35854000.bin | grep -i "connect\|send\|recv"
```

#### Outcome

| Item | Finding |
|------|---------|
| 🐛 Rootkit confirmed | Process `opencode` with 317 anonymous RWX regions |
| 🔗 C2 identified | Strings in dump confirm connection to IP 185.xxx.xxx.xxx |
| 🔐 Chain of custody | SHA256 for every artifact logged |
| ⏱ Downtime | **Zero** — database never interrupted |
| 📊 Report | JSON + CSV with full metadata for legal proceedings |

### Lessons Learned

1. **Always audit first** — LinSpec took 2 seconds and prevented a failed attempt at `/dev/mem`
2. **`/proc/kcore` is your friend** — Page-level access, no MCE (Machine Check Exception) risk
3. **Not every RWX is malware** — Context matters. JIT engines are legitimate; 317x ANON_BLOB in an unknown process is not
4. **Document the chain of custody** — SHA256 on every dump ensures forensic admissibility

---

## ● Blue Team Portfolio

### Why this toolkit demonstrates senior-level skills

| Skill | Demonstrated by |
|-------|----------------|
| **Systems programming (C)** | K-Scanner and LinSpec in pure C99, `/proc` manipulation, ncurses TUI |
| **Forensic shell scripting** | S.I.R.E.N with audit-aware logic, JSON parsing via grep |
| **Linux kernel internals** | W^X, STRICT_DEVMEM, kptr_restrict, ASLR, sysfs |
| **Forensic acquisition** | /dev/mem vs /proc/kcore trade-offs, SHA256 chain of custody |
| **Incident response** | Full workflow: triage → acquisition → analysis → reporting |
| **Blue Team mindset** | Read-only operation, zero-downtime production, forensic documentation |
| **Tool architecture** | Modular design with component integration via JSON protocol |

### For recruiters

This repository demonstrates the ability to **design, implement, and operate** a complete forensic ecosystem — not just using existing tools, but **building the infrastructure** that enables kernel-level incident response. Every component was built with:

- **Security first** — Passive operation, never modifies the target
- **Reliability** — Cryptographic integrity verification on every artifact
- **Resilience** — Automatic fallback between different memory interfaces
- **Professionalism** — Documentation, troubleshooting, and real-world use cases

---

## ● Repository Structure

```
Linux-Forensics-Toolkit/
│
├── K-Scanner/               ← RWX process analysis
│   ├── src/                 ├── core/ (kscanner.c, mem_analyzer, process_hunter)
│   │                       ├── modules/ (tui_engine, export_engine, regex_engine)
│   │                       └── utils/ (logger, memory_utils)
│   ├── include/             ├── public headers
│   ├── scripts/             ├── build, test, diagnostic
│   ├── docs/                ├── architecture, threat model, methodology
│   └── Makefile
│
├── LinSpec/                 ← Kernel hardening audit
│   ├── src/                 ├── main.c, memory_audit.c, system_audit.c
│   ├── include/             ├── headers
│   ├── docs/                ├── technical documentation
│   └── Makefile
│
├── SIREN/                       ← Memory acquisition
│   ├── src/                 ├── siren.sh
│   ├── dumps/               ├── extracted artifacts (.bin, .sha256, manifest.csv)
│   ├── docs/                ├── acquisition model, safety model
│   └── .gitignore
│
├── README.md                ← This file
└── LICENSE
```

Each subdirectory maintains its own documentation and independent Makefile. The toolkit can be used both as an integrated suite or as standalone tools.

---

## ● License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](./LICENSE)

*This project is licensed under the MIT License. Each subproject (K-Scanner, LinSpec, S.I.R.E.N) also maintains its own license under the same terms.*
