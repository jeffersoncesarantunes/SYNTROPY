#include <stdio.h>
#include "checks.h"

int main() {
    printf(BOLD "+---LinSpec---------------------------------------------------------------------+\n" RESET);
    printf(BOLD "|    Forensic Kernel Hardening Audit                                            |\n" RESET);
    printf(BOLD "+-------------------------------------------------------------------------------+\n\n" RESET);

    int p = 0, w = 0, v = 0;

    check_aslr(&p, &v);
    check_kptr_restrict(&p, &v);
    check_ptrace_scope(&p, &w);
    check_dmesg_restrict(&p, &v);
    check_bpf_jit(&p, &w);
    check_tcp_syncookies(&p, &w);
    check_unprivileged_userns(&p, &w);
    check_ip_forwarding(&p, &v);
    check_protected_symlinks(&p, &v);
    check_protected_hardlinks(&p, &v);
    check_kexec_load(&p, &w);
    check_dev_mem_restrict(&p, &v);
    check_entropy(&p, &w);
    check_spectre_v2(&p, &v, &w);
    check_meltdown(&p, &v, &w);

    printf(BOLD "\n+---Summary---------------------------------------------------------------------+\n" RESET);
    printf("|   " GRN "PASS: %02d" RESET " | " YEL "WARN: %02d" RESET " | " RED "VULN: %02d" RESET "                               |\n", p, w, v);
    printf("| [!] Audit finished. Security baseline report generated in reports/            |\n");
    printf("+-------------------------------------------------------------------------------+\n");

    export_reports(p, w, v);

    return 0;
}
