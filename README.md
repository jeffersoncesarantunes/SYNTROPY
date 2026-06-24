# SYNTROPY

Unified Linux Incident Response Toolkit -- Audit, Acquire, Analyze.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Core-C99-00599C?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![Language-Bash](https://img.shields.io/badge/Acquisition-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00A86B?style=flat-square)](#-roadmap)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Blue%20Team%20%7C%20DFIR-8A2BE2?style=flat-square)](#-overview)

---

## Etymology & Origin

The name SYNTROPY comes from the concept of **syntropy** -- the opposite of entropy.

Entropy pulls things toward disorder and chaos. Syntropy is the reverse: it's the tendency toward order, organization, and structure in complex systems. That idea maps directly onto what this toolkit does. When a system is under attack and you're staring at forensic chaos, SYNTROPY gives you the methodology and tools to restore order, keep a clear chain of evidence, and bring structure to the investigation.

---

## Overview

SYNTROPY is an open-source forensic ecosystem made up of three specialized tools that work together to **audit, acquire, and analyze** volatile evidence on Linux systems under investigation.

It's built for Blue Team and DFIR people who need the full memory incident response lifecycle:

| Phase | Tool | Objective |
|-------|------|-----------|
| **1. Triage** | LinSpec | Audit kernel hardening posture and identify vulnerabilities |
| **2. Acquisition** | S.I.R.E.N | Extract memory dump with awareness of the active security profile |
| **3. Analysis** | K-Scanner | Detect processes with suspicious RWX memory regions in real-time |

What sets it apart:

* **Read-only operation** -- no process injection, no kernel modification
* **Audit-aware acquisition** -- adapts strategy based on active kernel protections
* **Cryptographic integrity** -- SHA256 on every forensic artifact
* **Pure C99** (LinSpec, K-Scanner) and **Bash** (S.I.R.E.N) -- minimal dependencies (system libraries + ncurses for K-Scanner TUI)

---

## Components

### 1. LinSpec -- Kernel Hardening Audit

LinSpec checks critical Linux kernel security parameters in real-time and classifies each one as PASS, WARN, or VULN.

**What it looks at:**

| Category | Parameters |
|----------|-----------|
| Memory | ASLR, devmem_restrict |
| Kernel | kptr_restrict, dmesg_restrict, kexec_load_disabled |
| CPU | Spectre v2, Meltdown |
| Network | BPF JIT hardening, TCP syncookies, IP forwarding |
| System | Ptrace scope, user namespaces, protected symlinks/hardlinks |

**Output:** Structured `report.json` + `report.csv`, consumed by S.I.R.E.N so it can adapt its acquisition strategy.

```bash
sudo ./linspec

# Sample output:
# [ 01 ]  MEMORY   >  ASLR                              [+] [   PASS   ]
# [ 02 ]  KERNEL   >  Kernel Pointer Restriction        [-] [   VULN   ]
# [ 12 ]  MEMORY   >  DMA Restriction                   [+] [   PASS   ]
# [ 15 ]  CPU      >  Meltdown Mitigation               [+] [   PASS   ]
```

### 2. S.I.R.E.N -- Shell Interactive Runtime Entity Notifier

Volatile memory acquisition tool that's context-aware. It reads LinSpec's `report.json` and figures out the best extraction strategy automatically.

**Operation modes:**

| Option | Function | Source | Risk |
|--------|----------|--------|------|
| 1 | Map physical RAM | `/proc/iomem` | None |
| 2 | Verify extraction pipeline | `/proc/version` | None |
| 3 | Live memory extraction | `/dev/mem` (falls back to `/proc/kcore`) | Low |
| 4 | Advanced forensic bypass | `/proc/kcore` (ELF-aware) | Low |

**How it adapts based on audit data:**
- If `kptr_restrict > 0` it reads audit params for context
- If `spectre_v2 = 0` or `meltdown = 0` it warns about side-channel leaks during extraction

**Key improvements:**
- ELF-aware `/proc/kcore` extraction via Python (parses PT_LOAD segments)
- Non-interactive CLI mode: `--quick`, `--full`, `--test`, `--output`
- Post-dump content validation (entropy sampling, magic bytes)
- Persistent operation logging for chain of custody

```bash
sudo ./src/siren.sh          # Interactive menu
sudo ./src/siren.sh --full   # Headless full acquisition
```

### 3. K-Scanner -- Live Process Forensics

Scans every active process by reading `/proc/[PID]/maps` looking for memory regions with RWX (Read-Write-Execute) permissions. That's a direct violation of the W^X (Write XOR Execute) principle.

**What it catches:**
- `ANON_BLOB` -- Anonymous executable region (shellcode, fileless malware)
- `JIT_ENGINE` -- JIT compilation (Firefox, Python, Node.js, Discord)
- `VOLATILE_FS` -- RWX in `/tmp` or `/dev/shm`
- `PROC_STACK` -- Executable stack (exploit or insecure configuration)

```bash
sudo ./kscanner --json > alerts.json
```

**Interactive TUI:** Navigate processes, view real-time alerts, press ENTER to extract suspicious regions with automatic SHA256, strings, and hexdump generation.

---

## Features

* Full memory incident response lifecycle (triage -> acquisition -> analysis)
* Audit-aware acquisition strategy that adapts to kernel hardening level
* Real-time RWX memory violation detection
* Interactive ncurses-based forensic TUI
* Automatic SHA256 integrity chain on every artifact
* JSON/CSV structured forensic reports
* Modular architecture -- each tool works standalone or integrated
* Minimal dependencies (C99 + system libraries; ncurses for K-Scanner TUI)

---

## Example Output

```text
 PHASE 1 -- LinSpec Audit:

 [ 01 ]  MEMORY   >  Address Space Layout Randomization     [+] [   PASS   ]
 [ 02 ]  KERNEL   >  Kernel Pointer Restriction             [-] [   VULN   ]
 [ 05 ]  NETWORK  >  BPF JIT Compiler Hardening             [!] [   WARN   ]

 PHASE 2 -- S.I.R.E.N Acquisition:

 --> Address: 00001000-0009efff : System RAM [VALID]
 --> Address: 00100000-5aaeafff : System RAM [VALID]
 [+] Extraction via /proc/kcore -- 32 GB acquired
 [+] SHA256: a1b2c3d4e5f6...

 PHASE 3 -- K-Scanner Analysis:

 PID    PROCESS              STATUS          MAP_ADDR
 53220  suspicious-process   RWX ALERT       3ed35854000
 1132   python3              RWX ALERT       7fc163862000
 1426   Xorg                 SAFE            n/a
```

---

## How It Works

The three tools talk to each other through a shared forensic protocol -- `report.json`.

**LinSpec** talks to:

* `/proc/sys`
* `/sys/devices`

The audit flow goes like this:

1. Collect kernel security parameters
2. Normalize and classify values
3. Compare against a hardened baseline
4. Assign PASS / WARN / VULN states
5. Export `reports/report.json`

**S.I.R.E.N** talks to:

* `/proc/iomem`
* `/dev/mem`
* `/proc/kcore`

Acquisition flow:

1. Load LinSpec audit data (`report.json`)
2. Map valid System RAM regions via `/proc/iomem`
3. Pick the acquisition source (`/dev/mem` or `/proc/kcore`)
4. Dump physical memory with SHA256 integrity chain
5. Generate forensic report and manifest

**K-Scanner** talks to:

* `/proc/[PID]/maps`
* `/proc/[PID]/mem`

Analysis flow:

1. Parse `/proc/[PID]/maps`
2. Identify memory permissions (R / W / X)
3. Detect RWX violations (W^X policy breach)
4. Classify process behavior
5. Dump suspect regions with strings and disassembly

**Orchestration layer:**

* `syntropy-run.sh` -- Runs the full pipeline (LinSpec + S.I.R.E.N + K-Scanner) in one command
* `syntropy-bind.sh` -- Creates a unified `syntropy_report.json` from all tool outputs
* `syntropy-scan-offline.sh` -- Offline analysis of existing .bin dumps

---

## Quick Install

```bash
# Clone the unified toolkit
git clone https://github.com/jeffersoncesarantunes/SYNTROPY.git
cd SYNTROPY

# ---- LinSpec ----
cd LinSpec && make clean && make && cd ..

# ---- K-Scanner ----
cd K-Scanner && make clean && make && cd ..

# ---- SIREN ----
chmod +x S.I.R.E.N/src/siren.sh S.I.R.E.N/tools/kcore_extract.py

# Ready. Run as root:
sudo ./LinSpec/linspec
sudo ./S.I.R.E.N/src/siren.sh
sudo ./K-Scanner/kscanner --help
```

**Prerequisites:** `gcc`, `make`, `ncurses`, `binutils`, `coreutils`, `bash 4.x+`, root privileges.

### YARA (Optional)

[YARA](https://virustotal.github.io/yara/) is a pattern-matching engine that K-Scanner's `--yara` flag and the offline scanner use to identify malware signatures in memory dumps. You only need it if you're using the `--yara` option in `syntropy-run.sh` or `syntropy-scan-offline.sh`.

```bash
sudo pacman -S yara
```

---

## Incident Response Workflow

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

## Detailed Usage

### Phase 1: Audit with LinSpec

```bash
cd LinSpec
sudo ./linspec
```

The report lands in `reports/report.json` and S.I.R.E.N picks it up automatically in the next phase.

**Things to watch for:**
- `kptr_restrict = 0` -- Kernel pointers visible (information leak)
- `devmem_restrict = 0` -- `/dev/mem` unrestricted (extraction risk)
- `spectre_v2 = 0` -- CPU vulnerable to Spectre
- `bpf_jit_harden = 0` -- BPF JIT without hardening

### Phase 2: Acquisition with S.I.R.E.N

```bash
cd S.I.R.E.N
sudo ./src/siren.sh
```

You get an interactive menu:

```
1) Map Physical Memory (iomem)
2) Verify Extraction Pipeline
3) Live Memory Extraction (/dev/mem)
4) Advanced Forensic Bypass (kcore)
5) Exit
```

**Note:** Option 3 attempts `/dev/mem` but modern kernels restrict it via `CONFIG_STRICT_DEVMEM` — the tool falls back to `/proc/kcore` automatically.

**Recommendation:** Option 4 (kcore) uses Python to parse PT_LOAD segments from `/proc/kcore` (ELF-aware extraction), producing a dump with segment metadata. It's the most complete and stable method.

Non-interactive usage:
```bash
sudo ./src/siren.sh --quick                    # 100MB triage
sudo ./src/siren.sh --full --output /evidence/  # Full + custom dir
```

### Phase 3: Analysis with K-Scanner

```bash
cd K-Scanner
sudo ./kscanner          # Interactive TUI mode
sudo ./kscanner --json   # JSON export (headless)
sudo ./kscanner --csv    # CSV export (headless)
```

**TUI controls:**
- Navigate processes with arrow keys
- Red rows = RWX ALERT
- Green rows = SAFE
- Press ENTER on a suspicious process to extract the RWX region
- Press Q to exit

**Live regex search across process memory:**
```bash
sudo ./kscanner --live <PID> "<regex>"
```

---

## Why

Incident response on Linux has always lacked a unified, audit-aware forensic pipeline. Most tools work in isolation -- your kernel auditor can't talk to your memory acquirer, and your RWX detector has no idea what the system's protection state looks like.

SYNTROPY fixes that by:

* Feeding kernel audit data directly into acquisition decisions
* Giving you a repeatable three-phase forensic workflow
* Keeping cryptographic integrity at every stage
* Running with zero system modification
* Letting you collect evidence in production without downtime

It turns raw kernel telemetry into a structured, court-ready forensic chain.

---

## Project in Action

![Overview](K-Scanner/Images/kscanner1.png)
*1 - Live forensic mode identifying RWX memory regions across active processes.*

![Acquisition](S.I.R.E.N/Images/siren3.png)
*2 - Full memory acquisition with integrity verification and structured reporting.*

![Validation](LinSpec/Images/linspec3.png)
*3 - Cross-validation of kernel audit results against live system state.*

---

## Operational Integrity

SYNTROPY was designed for live-response environments where you can't afford to break things:

* Read-only across all components
* No process injection or kernel modification
* Audit-aware fallback between memory interfaces
* Cryptographic integrity on every forensic artifact
* Graceful failure when access is restricted
* Zero-downtime evidence collection in production

---

## Deployment

### Requirements

* Linux Kernel 5.x or newer
* gcc, make
* ncurses (K-Scanner)
* binutils, coreutils
* Bash 4.x+
* Root privileges
* UTF-8 compatible terminal

---

## Scripts

SYNTROPY comes with three automation scripts that wire together the full forensic pipeline between LinSpec, S.I.R.E.N, and K-Scanner. They're all independent -- they call the existing tool binaries and process their output without modifying anything in the tools themselves.

### Quick Start

```bash
# Full pipeline: audit -> acquire -> analyze -> unified report
sudo ./scripts/syntropy-run.sh

# With YARA rule analysis
sudo ./scripts/syntropy-run.sh --yara /path/to/rules.yara

# Custom output directory
sudo ./scripts/syntropy-run.sh --out /evidence/case-001
```

### syntropy-run.sh -- Orchestrator

Runs the complete three-phase workflow and collects everything into a single case directory:

```bash
sudo ./scripts/syntropy-run.sh [--yara <rules.yara>] [--out <dir>]
```

Here's what it does:

1. **LinSpec** -- kernel hardening audit (`report.json`)
2. **S.I.R.E.N** -- memory acquisition via kcore (`.bin` dump)
3. **K-Scanner** -- live RWX analysis (`kscan_results.json`)
4. **syntropy-bind.sh** -- unified report generation

All artifacts go under `/tmp/syntropy/FOR-<timestamp>/` (or wherever `--out` points):

```
<case-root>/
├── audit/
│   └── report.json
├── acquire/
│   ├── full_scan_*.bin
│   └── report_*.json
├── analyze/
│   └── kscan_results.json
└── syntropy_report.json    <- unified forensic report
```

### syntropy-bind.sh -- Unified Report Generator

Merges LinSpec, S.I.R.E.N, and K-Scanner output into one forensic report with chain of custody:

```bash
# From a completed case directory
./scripts/syntropy-bind.sh /tmp/syntropy/FOR-20260603-153022/

# With explicit acquisition hash
./scripts/syntropy-bind.sh /tmp/syntropy/FOR-20260603-153022/ a1b2c3d4e5f6...
```

Generates `syntropy_report.json` with:
- Full audit-acquire-analyze timeline
- RWX alert summary and process list
- SHA256 chain of custody
- Artifact paths for all phases

### syntropy-scan-offline.sh -- Offline Dump Analysis

Scans a raw memory dump (`.bin`) without needing the original system. Uses the same toolchain K-Scanner relies on (`sha256sum`, `strings`, `hexdump`, `objdump`, `yara`):

```bash
# Basic analysis
./scripts/syntropy-scan-offline.sh dumps/binaries/full_scan_20260603.bin

# With YARA rules
./scripts/syntropy-scan-offline.sh dumps/binaries/full_scan_20260603.bin --yara rules/malware.yara
```

Artifacts generated alongside the dump file:
```
full_scan_20260603.bin          <- original dump
full_scan_20260603.bin.sha256   <- integrity hash
full_scan_20260603.bin.strings.txt  <- extracted strings
full_scan_20260603.bin.hex.txt  <- hexadecimal preview
full_scan_20260603.bin.disasm.txt   <- x86-64 disassembly
full_scan_20260603.bin.yara.txt <- YARA rule matches (if --yara)
```

---

## Repository Structure

```text
SYNTROPY/
│
├── K-Scanner/
│   ├── src/
│   │   ├── core/
│   │   ├── modules/
│   │   └── utils/
│   ├── include/
│   ├── scripts/
│   ├── docs/
│   └── Makefile

├── LinSpec/
│   ├── src/
│   ├── include/
│   ├── docs/
│   └── Makefile

├── S.I.R.E.N/
│   ├── src/
│   ├── lib/
│   ├── tools/
│   ├── dumps/
│   ├── docs/
│   └── .gitignore

├── scripts/
│   ├── syntropy-run.sh
│   ├── syntropy-bind.sh
│   └── syntropy-scan-offline.sh

├── .gitmodules

├── LICENSE

├── README.md

└── SECURITY.md
```

Each subdirectory keeps its own docs and an independent Makefile. You can use the toolkit as an integrated suite or grab individual tools.

---

## Tech Stack

* **Core Language:** C99 (LinSpec, K-Scanner)
* **Acquisition Layer:** Bash 4.x+ (S.I.R.E.N)
* **Data Sources:** `/proc`, `/sys`, `/dev/mem`
* **Interface:** ncurses TUI (K-Scanner)
* **Hashing:** SHA256
* **Forensic Reports:** JSON / CSV
* **Build System:** GNU Make
* **Target:** Linux Kernel 5.x / 6.x

---

## Roadmap

* [x] Kernel hardening audit engine (LinSpec)
* [x] Audit-aware adaptive memory acquisition (S.I.R.E.N)
* [x] Real-time RWX detection with ncurses TUI (K-Scanner)
* [x] Cryptographic integrity chain (SHA256)
* [x] JSON/CSV structured forensic reporting
* [x] Cross-tool integration via `report.json` protocol
* [x] Live regex memory hunting (K-Scanner `--live`)
* [x] eBPF real-time RWX telemetry (K-Scanner `--bpf`)
* [x] Disassembly and shellcode pattern detection (K-Scanner)
* [x] YARA rule-based scan (K-Scanner `--yara`)
* [x] Container-aware deep inspection (K-Scanner)
* [x] **Automated orchestration pipeline** (`syntropy-run.sh`)
* [x] **Unified forensic reporting** (`syntropy-bind.sh`)
* [x] **Offline dump analysis** (`syntropy-scan-offline.sh`)
* [ ] Automated remediation suggestions

---

## Documentation

[![Docs-LinSpec](https://img.shields.io/badge/LinSpec-Architecture-002B36?style=flat-square\&logo=linux\&logoColor=white)](./LinSpec/docs/architecture.md)
[![Docs-SIREN](https://img.shields.io/badge/S.I.R.E.N-Acquisition-00599C?style=flat-square\&logo=linux\&logoColor=white)](./S.I.R.E.N/docs/ACQUISITION_MODEL.md)
[![Docs-KScanner](https://img.shields.io/badge/K--Scanner-Methodology-003366?style=flat-square\&logo=linux\&logoColor=white)](./K-Scanner/docs/forensic_methodology.md)
[![Docs-ThreatModel](https://img.shields.io/badge/Threat-Model-CC0000?style=flat-square\&logo=dependabot\&logoColor=white)](./K-Scanner/docs/threat_model.md)

---

## License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square\&logo=opensourceinitiative\&logoColor=white)](./LICENSE)

*This project is licensed under the MIT License. Each subproject (K-Scanner, LinSpec, S.I.R.E.N) also maintains its own license under the same terms.*
