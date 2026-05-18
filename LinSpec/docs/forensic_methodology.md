# ● LinSpec Forensic Methodology

## ● Purpose

LinSpec operates as the **Initial Triage Layer** (Phase 0) in a digital forensic investigation. 

Before volatile memory is captured, LinSpec evaluates the environment's integrity. Its primary goal is to determine if the kernel's defensive posture was compromised and to provide the technical intelligence required for safe memory acquisition.

---

## ● Forensic Philosophy

LinSpec adheres to three core principles designed for operational security:

- **Non-Intrusive Analysis**: Operates strictly in user-space with read-only access to `/proc` and `/sys` interfaces, ensuring no "forensic footprints" are left that could alter system evidence.
- **Deterministic Evaluation**: Uses a fixed security baseline to ensure that audit results are reproducible and verifiable.
- **Ecosystem Symbiosis**: Generates a machine-readable "Contract" (`report.json`) that drives the behavior of automated acquisition tools.

---

## ● Investigation Flow

### 1. Baseline Validation
Identify critical deviations from hardened kernel configurations (e.g., ASLR disabled or Kernel Pointer leakage).

### 2. Exposure Mapping
Map the attack surface by detecting weak points—such as unprivileged user namespaces or lack of CPU mitigations—that could have facilitated privilege escalation.

### 3. Intelligence for Acquisition (S.I.R.E.N Integration)
Produce reports that dictate the **Acquisition Strategy**. For example:
- **Lockdown Detection:** If LinSpec detects a Kernel Lockdown, S.I.R.E.N pivots to `/proc/kcore`.
- **Integrity Baseline:** Provides the expected state of pointers, allowing S.I.R.E.s to detect if memory reads are being spoofed or padded with NULL bytes.

---

## ● Key Insight

LinSpec is a **Post-Mortem & Live Triage** tool. It does not look for malware signatures; instead, it answers the fundamental forensic question:

> "Did the system's runtime configuration provide an environment where an exploit could succeed and how can we safely extract evidence from it?"

---

## ● Integration with the Forensic Ecosystem

LinSpec is the foundational pillar of a three-stage specialized workflow:

1. **LinSpec (Audit)**: Establishes the security baseline and acquisition parameters.
2. **S.I.R.E.N (Acquisition)**: Performs adaptive memory capture based on LinSpec's triage artifacts.
3. **K-Scanner (Analysis)**: Scans for malicious artifacts, patterns, and memory anomalies.

---

## ● Forensic Value Matrix

| Phase | Tool | Forensic Output |
| :--- | :--- | :--- |
| **Triage (Phase 0)** | **LinSpec** | Kernel security baseline, lockdown status & JSON audit contract. |
| **Acquisition (Phase 1)** | **S.I.R.E.N** | Validated forensic memory dump (.bin) and integrity manifest. |
| **Analysis (Phase 2)** | **K-Scanner** | Identification of threats, rootkits, and pattern-matched artifacts. |

---

## ● Data Integrity & Chain of Custody

To ensure the integrity of the audit, LinSpec generates structured artifacts (`report.json` and `report.csv`). These files should be hashed immediately alongside the memory dump to maintain a clear chain of custody and to prove the environmental context at the moment of acquisition.
