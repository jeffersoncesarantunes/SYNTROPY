# ● Threat Model

## ● Objective

This document defines the attacker capabilities and attack vectors that LinSpec evaluates. By mapping defensive configurations to known exploitation techniques, LinSpec provides a clear picture of the system's resilience against local and remote threats.

---

## ● Assumed Attacker Capabilities

- **Local Access**: Unprivileged user shell access.
- **Code Execution**: Ability to compile and execute arbitrary binaries or scripts (e.g., Python, C).
- **Exploitation Knowledge**: Familiarity with modern kernel exploitation (ROP chains, heap spraying, and side-channel analysis).

---

## ● Evaluated Attack Vectors

### 1. Information Disclosure (Reconnaissance)
- **Vector**: Leakage of kernel symbol addresses via `/proc/kallsyms` or sensitive logs in `dmesg`.
- **Attacker Goal**: Bypass **KASLR** by identifying the kernel's base address in memory.
- **LinSpec Defense**: Audits `kptr_restrict` and `dmesg_restrict`.

### 2. Privilege Escalation & Persistence
- **Vector**: Abuse of `ptrace` to inject code into high-privilege processes or utilizing unprivileged user namespaces to escape containers/sandboxes.
- **Attacker Goal**: Gain root privileges or establish a persistent backdoor.
- **LinSpec Defense**: Audits `ptrace_scope` and `unprivileged_userns_clone`.

### 3. Kernel Space Exploitation
- **Vector**: Exploiting the BPF JIT compiler through "JIT spraying" or loading malicious modules via `kexec`.
- **Attacker Goal**: Execute arbitrary code directly within the kernel context (Ring 0).
- **LinSpec Defense**: Audits `bpf_jit_harden` and `kexec_load_disabled`.

### 4. Side-Channel & Microarchitectural Attacks
- **Vector**: Leveraging hardware flaws in the CPU pipeline (Spectre, Meltdown).
- **Attacker Goal**: Read sensitive data (passwords, keys) across security boundaries.
- **LinSpec Defense**: Audits CPU vulnerability mitigation status.

---

## ● Defensive Mapping Matrix

| Attack Type | Criticality | LinSpec Audit Focus | Mitigation Goal |
| :--- | :--- | :--- | :--- |
| **Info Leak** | Medium | `kptr_restrict`, `dmesg_restrict` | Entropy preservation (KASLR). |
| **Code Injection** | High | `ptrace_scope`, `nx_stack` | Prevention of process hijacking. |
| **Denial of Service** | Low | `tcp_syncookies` | Resource availability during SYN floods. |
| **Kernel Exploit** | Critical | `bpf_jit_harden`, `kexec_disabled` | Kernel runtime integrity. |
| **Side-channel** | High | CPU Vulnerability Interfaces | Hardware-level isolation. |

---

## ● Key Insight

LinSpec evaluates **Attack Feasibility**.

A system with multiple "VULN" ratings does not necessarily mean it is currently compromised, but it indicates that the **cost of attack** is significantly lower. In a forensic context, these findings suggest which paths an intruder likely took to gain control.
