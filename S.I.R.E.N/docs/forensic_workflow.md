# ● Forensic Workflow

This document outlines the recommended workflow when using the S.I.R.E.N ecosystem in a professional forensic investigation.

---

## 1. Pre-Acquisition Audit (Stage 0)

Before acquiring memory, execute LinSpec to baseline the kernel's defensive state. This determines which memory interfaces are accessible and if mitigations like KASLR or Kernel Lockdown are active.

- Action: Run LinSpec and ensure report.json is generated in the shared directory.
- Goal: Provide S.I.R.E.N with the necessary intelligence to select the best acquisition path.

---

## 2. Acquisition Phase

Run S.I.R.E.N with root privileges. The tool will automatically detect the LinSpec audit and adapt:

sudo ./src/siren.sh

Critical Decision Point:
If the tool detects a restricted memory region:
- Option 1 & 2: Attempt extraction (may lead to system freeze if hardware-protected).
- Option 3 (Ignore): Recommended for restricted ranges to maintain system stability and skip NULL-padded regions.

---

## 3. Integrity & Validation

After acquisition, verify that the dump contains actual physical data rather than kernel-injected NULL bytes:

1. Hash Verification:
   sha256sum -c dumps/mem_dump.bin.sha256

2. Entropy Check (NULL Detection):
   Use od or hexdump to ensure the dump isn't a "phantom file" (all zeros):
   od -An -N64 -x dumps/mem_dump.bin

---

## 4. Rapid Triage (Artifact Extraction)

Utilize the automated strings extraction for immediate evidence gathering:

grep -Ei "password|user|ssh-key|config" dumps/mem_dump.txt

This helps identify volatile artifacts such as decrypted credentials or active configuration files that do not exist on the physical disk.

---

## 5. Low-Level Post-Analysis

For deeper inspection of the generated .bin dumps, utilize standard forensic external tools:

- Hexadecimal Inspection: hexdump -C dump.bin | less
- Pattern Matching: Use grep with the --binary-files=text flag.
- Structural Analysis: Load the dump into frameworks like Volatility or specialized memory scanners.

---

## 6. Analysis Environment Best Practices

- Isolation: Always transfer large .bin dumps to a dedicated forensic workstation.
- Persistence: Keep the manifest.csv and report.json alongside the dump to maintain the chain of custody and environmental context.
- Evidence Preservation: Once validated, move the dump to read-only storage.

---

*This workflow ensures a transition from automated kernel audit to controlled, stable memory acquisition.*
