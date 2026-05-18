#ifndef CHECKS_H
#define CHECKS_H

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BOLD  "\x1B[1m"
#define RESET "\x1B[0m"

void check_aslr(int *p, int *v);
void check_kptr_restrict(int *p, int *v);
void check_ptrace_scope(int *p, int *w);
void check_dmesg_restrict(int *p, int *v);
void check_bpf_jit(int *p, int *w);
void check_tcp_syncookies(int *p, int *w);
void check_unprivileged_userns(int *p, int *w);
void check_ip_forwarding(int *p, int *v);
void check_protected_symlinks(int *p, int *v);
void check_protected_hardlinks(int *p, int *v);
void check_kexec_load(int *p, int *w);
void check_dev_mem_restrict(int *p, int *v);
void check_entropy(int *p, int *w);
void check_spectre_v2(int *p, int *v, int *w);
void check_meltdown(int *p, int *v, int *w);

void export_reports(int p, int w, int v);

#endif
