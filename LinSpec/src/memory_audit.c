#include <stdio.h>
#include "checks.h"

void print_mem_result(int id, const char *cat, const char *desc, const char *symbol, const char *color, const char *status) {
    printf("    [ %02d ]  %-7s >  %-35s %s%s%s [  %-5s%s ]\n", 
           id, cat, desc, color, symbol, RESET, status, RESET);
}

void check_aslr(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/randomize_va_space", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 2) { 
        print_mem_result(1, "MEMORY", "Address Space Layout Randomization", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_mem_result(1, "MEMORY", "Address Space Layout Randomization", "[-]", BOLD RED, "VULN");
        (*v)++; 
    }
}

void check_dev_mem_restrict(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/devmem_restrict", "r");
    if (fp) {
        int val = 0;
        fscanf(fp, "%d", &val);
        fclose(fp);
        if (val == 1) {
            print_mem_result(12, "MEMORY", "Direct Memory Access Restriction", "[+]", BOLD GRN, "PASS");
            (*p)++;
        } else {
            print_mem_result(12, "MEMORY", "Direct Memory Access Restriction", "[-]", BOLD RED, "VULN");
            (*v)++;
        }
    } else {
        print_mem_result(12, "MEMORY", "Direct Memory Access Restriction", "[!]", BOLD YEL, "WARN");
        (*v)++;
    }
}
