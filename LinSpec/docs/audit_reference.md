# ● Audit Reference

## ● Overview

This document provides a technical reference for the kernel parameters and hardware security features audited by LinSpec. It serves as a guide for interpreting forensic results and understanding the underlying security mechanisms.

---

## ● Memory Protection

### ASLR (kernel.randomize_va_space)
- **Path:** `/proc/sys/kernel/randomize_va_space`
- **Expected Value:** `2` (Full Randomization)
- **Forensic Evidence:** When enabled, the stack, virtual dynamic shared object (vDSO) page, and shared memory regions are randomized.
- **Risk:** 
  - **Disabled (0) or Partial (1):** Predictable memory layout.
  - **Impact:** Significant increase in the success rate of exploitation techniques such as ROP (Return-Oriented Programming) and ret2libc.

---

## ● Kernel Hardening

### kptr_restrict
- **Path:** `/proc/sys/kernel/kptr_restrict`
- **Expected Value:** `2`
- **Forensic Evidence:** Addresses in `/proc/kallsyms` will be displayed as zeros (`0000000000000000`) for unprivileged users.
- **Risk:**
  - **Leakage:** Disclosure of kernel symbol addresses.
  - **Impact:** Direct KASLR (Kernel Address Space Layout Randomization) bypass.

### dmesg_restrict
- **Path:** `/proc/sys/kernel/dmesg_restrict`
- **Expected Value:** `1`
- **Risk:**
  - **Information Disclosure:** Privileged kernel logs exposed to unprivileged users, potentially leaking sensitive system information.

---

## ● System Controls

### ptrace_scope (Yama)
- **Path:** `/proc/sys/kernel/yama/ptrace_scope`
- **Expected Value:** `1` (Restricted Ptrace) or higher.
- **Risk:**
  - **Process Injection:** Ability for malicious processes to attach to and inject code into other running processes belonging to the same user.

### unprivileged_userns_clone
- **Path:** `/proc/sys/kernel/unprivileged_userns_clone`
- **Expected Value:** `0` (Disabled)
- **Risk:**
  - **Sandbox Escape:** Unprivileged users creating new namespaces, often used as a vector for privilege escalation exploits.

---

## ● Network Stack

### tcp_syncookies
- **Path:** `/proc/sys/net/ipv4/tcp_syncookies`
- **Expected Value:** `1`
- **Risk:**
  - **Denial of Service:** Vulnerability to SYN Flood attacks, which can exhaust system resources and disrupt network services.

### bpf_jit_harden
- **Path:** `/proc/sys/net/core/bpf_jit_harden`
- **Expected Value:** `2`
- **Risk:**
  - **JIT Spraying:** Exploitation of the BPF Just-In-Time compiler to execute arbitrary code in the kernel context.

---

## ● CPU Mitigations

### Hardware Vulnerabilities (Spectre, Meltdown, L1TF, etc.)
- **Source:** `/sys/devices/system/cpu/vulnerabilities/`
- **Forensic States:**
  - **Mitigated:** The kernel has active software/hardware defenses.
  - **Vulnerable:** The system is susceptible to side-channel attacks.
  - **Not affected:** The CPU hardware is not susceptible to the specific vulnerability.

---

## ● Status Logic Summary

LinSpec evaluates data against a hardened security baseline to produce the following indicators:

| Status | Meaning | Forensic Significance |
| :--- | :--- | :--- |
| **PASS** | Secure configuration | Alignment with hardened baseline. |
| **WARN** | Potential risk | Configuration deviates from strict hardening but may be necessary for compatibility. |
| **VULN** | Exploitable condition | Critical gap identified; high priority for remediation. |
