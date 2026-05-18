#!/usr/bin/env bash

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "${RED}[!] Error: Elevated privileges required.${NC}" && exit 1

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
BASE_DUMPS_DIR="$(dirname "$SCRIPT_DIR")/dumps"
BIN_DIR="$BASE_DUMPS_DIR/binaries"
REP_DIR="$BASE_DUMPS_DIR/reports"
CHK_DIR="$BASE_DUMPS_DIR/checksums"

mkdir -p "$BIN_DIR" "$REP_DIR" "$CHK_DIR"

LINSPEC_REPORT="$(dirname "$SCRIPT_DIR")/../LinSpec/reports/report.json"

LOADED_AUDIT=false
AUDIT_KPTR=1
AUDIT_PTRACE=1
AUDIT_DMESG=1
AUDIT_SPECTRE=1
AUDIT_MELTDOWN=1

load_linspec_audit() {
    if [[ -f "$LINSPEC_REPORT" ]]; then
        AUDIT_KPTR=$(grep -Po '"kptr_restrict": \K[^,]*' "$LINSPEC_REPORT")
        AUDIT_PTRACE=$(grep -Po '"ptrace_scope": \K[^,]*' "$LINSPEC_REPORT")
        AUDIT_DMESG=$(grep -Po '"dmesg_restrict": \K[^,]*' "$LINSPEC_REPORT")
        AUDIT_SPECTRE=$(grep -Po '"spectre_v2": \K[^,]*' "$LINSPEC_REPORT")
        AUDIT_MELTDOWN=$(grep -Po '"meltdown": \K[^,]*' "$LINSPEC_REPORT")
        LOADED_AUDIT=true
        return 0
    fi
    return 1
}

generate_reports() {
    local file_path=$1 method=$2 hash=$3 ts=$4
    local timestamp=${ts:-$(date +%Y%m%d_%H%M%S)}
    local hostname=$(hostname)
    local kernel=$(uname -r)
    local size=$(stat -c%s "$file_path" 2>/dev/null || echo "0")
    local json_file="$REP_DIR/report_$timestamp.json"
    
    printf "{\n  \"timestamp\": \"%s\",\n  \"hostname\": \"%s\",\n  \"kernel\": \"%s\",\n  \"method\": \"%s\",\n  \"audit_aware\": %s,\n  \"evidence\": {\n    \"file\": \"%s\",\n    \"size_bytes\": %s,\n    \"sha256\": \"%s\"\n  }\n}\n" \
        "$timestamp" "$hostname" "$kernel" "$method" "$LOADED_AUDIT" "$(basename "$file_path")" "$size" "$hash" > "$json_file"
    
    local csv_file="$REP_DIR/manifest.csv"
    [[ ! -f "$csv_file" ]] && echo "timestamp,hostname,method,file,size,sha256" > "$csv_file"
    echo "$timestamp,$hostname,$method,$(basename "$file_path"),$size,$hash" >> "$csv_file"
    
    echo -e "${GREEN}[+] Reports generated in $REP_DIR${NC}"
}

check_storage() {
    local ram_size=$(grep MemTotal /proc/meminfo | awk '{print $2 * 1024}')
    local disk_free=$(df -B1 "$BASE_DUMPS_DIR" | awk 'NR==2 {print $4}')
    if [[ -n "$ram_size" && -n "$disk_free" && "$ram_size" -gt "$disk_free" ]]; then
        echo -e "${YELLOW}[!] WARNING: RAM size exceeds available disk space.${NC}"
        read -p "Proceed with acquisition? (y/N): " choice
        [[ "$choice" != "y" ]] && exit 1
    fi
}

map_system_ram() {
    echo -e "${CYAN}[+] Mapping Physical System RAM regions...${NC}"
    if [[ "$AUDIT_KPTR" -eq 0 ]]; then
        echo -e "${YELLOW}[!] Kernel Pointers Leaking: Sensitive addresses might be visible in mapping.${NC}"
    fi
    grep "System RAM" /proc/iomem | while read -r line; do
        echo -e "  --> Address: ${YELLOW}${line}${NC} [VALID]"
    done
}

stream_analysis() {
    local source=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_file="$BIN_DIR/mem_dump_$timestamp.bin"
    
    echo -e "${CYAN}[*] Starting Pipeline: $source${NC}"
    
    if [[ "$source" == "/dev/mem" ]]; then
        echo -e "${RED}[!] ACTION REQUIRED: If prompted by the Kernel, select option 3 (Ignore) to prevent system freeze.${NC}"
    fi

    if [[ "$AUDIT_PTRACE" -gt 0 && "$source" != "/proc/version" ]]; then
        echo -e "${YELLOW}[!] Yama Ptrace active. Process memory attachment may be restricted.${NC}"
    fi

    if [[ "$source" == "/dev/mem" || "$source" == "/proc/kcore" ]]; then
        [[ "$source" == "/dev/mem" ]] && check_storage
        dd if="$source" bs=1M count=100 conv=noerror,sync status=progress > "$output_file" 2>/dev/null
    else
        cat "$source" > "$output_file"
    fi
    
    local hash=$(sha256sum "$output_file" | awk '{print $1}')
    sha256sum "$output_file" > "$CHK_DIR/mem_dump_$timestamp.bin.sha256"
    strings "$output_file" > "$BIN_DIR/mem_dump_$timestamp.txt"
    
    generate_reports "$output_file" "Live Extraction ($source)" "$hash" "$timestamp"
    echo -e "${GREEN}[+] Pipeline completed successfully.${NC}"
}

automated_extraction() {
    check_storage
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_file="$BIN_DIR/full_scan_$timestamp.bin"
    local source="/dev/mem"
    local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local ram_mb=$((ram_kb / 1024))
    
    if [[ "$AUDIT_KPTR" -gt 0 ]]; then
        echo -e "${CYAN}[i] LinSpec: Kptr_restrict active. Using /proc/kcore for better symbol resolution.${NC}"
        source="/proc/kcore"
    fi

    if [[ "$AUDIT_SPECTRE" -eq 0 || "$AUDIT_MELTDOWN" -eq 0 ]]; then
        echo -e "${RED}[!] CPU VULNERABLE: Side-channel leaks possible during extraction.${NC}"
    fi
    
    echo -e "${YELLOW}[!] Initiating Automated Extraction via $source...${NC}"
    > "$output_file"
    
    if [[ "$source" == "/dev/mem" ]]; then
        grep "System RAM" /proc/iomem | while read -r line; do
            range=$(echo $line | cut -d' ' -f1)
            start_hex=$(echo $range | cut -d'-' -f1)
            end_hex=$(echo $range | cut -d'-' -f2)
            start=$((16#$start_hex))
            end=$((16#$end_hex))
            size=$((end - start))
            
            echo -e "${CYAN}[i] Extracting range: $range ($((size/1024/1024)) MB)${NC}"
            dd if=/dev/mem bs=4k skip=$((start/4096)) count=$((size/4096)) conv=noerror,sync status=none >> "$output_file"
        done
    else
        echo -e "${CYAN}[*] Extraction: Physical RAM Size: ${ram_mb} MB${NC}"
        dd if=/proc/kcore bs=1M count=$ram_mb conv=noerror,sync status=progress >> "$output_file" 2>/dev/null
    fi

    echo -e "${CYAN}[*] Validating dump integrity...${NC}"
    local dump_size=$(stat -c%s "$output_file" 2>/dev/null || echo 0)
    if [[ "$dump_size" -lt 4096 ]]; then
        echo -e "${RED}[!] WARNING: Dump is too small (${dump_size} bytes) - read may have failed.${NC}"
        echo -e "${YELLOW}[i] Action Required: Check CONFIG_STRICT_DEVMEM or use 'iomem=relaxed'.${NC}"
    fi
    
    if [[ -s "$output_file" ]]; then
        local hash=$(sha256sum "$output_file" | awk '{print $1}')
        sha256sum "$output_file" > "$CHK_DIR/full_scan_$timestamp.bin.sha256"
        generate_reports "$output_file" "Automated Scan ($source)" "$hash" "$timestamp"
        echo -e "${GREEN}[+] Extraction finalized.${NC}"
    else
        echo -e "${RED}[!] Error: Extraction failed.${NC}"
    fi
}

while true; do
    clear
    load_linspec_audit
    echo -e "\n${GREEN}🐧 S.I.R.E.N - Shell Interactive Runtime Entity Notifier${NC}"
    
    if $LOADED_AUDIT; then
        echo -e "${GREEN}[Audit Loaded from LinSpec]${NC}"
    fi

    echo -e "${CYAN}---------------------------------------------------------${NC}"
    echo "1) Map Physical Memory (iomem)"
    echo "2) Verify Extraction Pipeline"
    echo "3) Live Memory Extraction (/dev/mem)"
    echo "4) Advanced Forensic Bypass (kcore)"
    echo "5) Exit"
    echo -e "${CYAN}---------------------------------------------------------${NC}"
    
    read -p "Select an option: " opt
    case $opt in
        1) map_system_ram ;;
        2) stream_analysis "/proc/version" ;;
        3) stream_analysis "/dev/mem" ;;
        4) automated_extraction ;;
        5) exit 0 ;;
        *) sleep 1 ;;
    esac
    
    echo -e "\n${CYAN}-- Press ENTER to return to menu --${NC}"
    read
done
