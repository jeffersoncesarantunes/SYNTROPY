# ● Architecture

## ● Overview

LinSpec is a modular, high-performance C-based auditing tool designed for real-time kernel hardening verification and forensic triage. It serves as the intelligence layer for the forensic ecosystem.

---

## ● Components

### main.c
- **Entry Point**: Handles command-line arguments and initialization.
- **Orchestration**: Manages the sequence of audit modules and final report generation.

### memory_audit.c
- **Integrity Checks**: Validates `ASLR`, `NX` stack, and `KASLR` state.
- **Pointer Security**: Inspects kernel pointer visibility (`kptr_restrict`).

### system_audit.c
- **Kernel Constraints**: Audits `sysctl` parameters, sandboxing flags, and `kexec` status.
- **Hardware Mitigations**: Verifies CPU-level defenses against side-channel attacks (Spectre/Meltdown).

### checks.h
- **Baseline Definitions**: Contains the security thresholds and logic used to determine PASS, WARN, or VULN status.

---

## ● Data Sources

LinSpec follows a **Passive Inspection** model, interfacing directly with:

- `/proc/sys` → Runtime kernel configuration and security parameters.
- `/sys/devices/system/cpu/vulnerabilities` → Hardware-level mitigation status.
- `/proc/kallsyms` → Runtime validation of address space randomization.

---

## ● Execution Flow

1. **Initialization**: Setup of environment and forensic baseline parameters.
2. **Data Collection**: Sequential reading of kernel and hardware interfaces.
3. **Logic Evaluation**: Comparison of live state against the defined security standard.
4. **Report Generation**: Output to terminal UI and export of the **Audit Contract** (JSON/CSV).

---

## ● The Audit Contract (Integration Layer)

The primary architectural output of LinSpec is the `report.json` file. This file acts as a technical contract for the ecosystem:

- **S.I.R.E.N Integration**: The acquisition engine parses this JSON to detect Kernel Lockdown or restricted pointers, automatically adjusting its extraction method (/dev/mem vs /proc/kcore).
- **K-Scanner Integration**: Provides the analysis layer with the ASLR/KASLR state, enabling precise memory offset calculations during pattern matching.

---

## ● Design Principles

- **Zero Dependencies**: Pure C99, requiring only standard libraries (`libc`).
- **Forensic Safety**: Strictly read-only operations; no system state is modified.
- **Operational Integrity**: Stateless execution to ensure the audit does not leave a footprint on the kernel's configuration.

---

*LinSpec is designed to be the foundational intelligence provider for automated forensic pipelines.*
