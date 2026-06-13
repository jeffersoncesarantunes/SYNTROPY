#!/usr/bin/env bash
set -euo pipefail

DUMP="${1:?Usage: $0 <dump.bin> [--yara <rules.yara>]}"
YARA_RULE=""

if [[ "${2:-}" == "--yara" && -n "${3:-}" ]]; then
    YARA_RULE="$3"
fi

if [[ ! -f "$DUMP" ]]; then
    printf "\033[31m[!]\033[0m File not found: %s\n" "$DUMP"
    exit 1
fi

if [[ -n "$YARA_RULE" && ! -f "$YARA_RULE" ]]; then
    printf "\033[31m[!]\033[0m YARA rule file not found: %s\n" "$YARA_RULE"
    exit 1
fi

printf "\033[36m[SYNTROPY]\033[0m Scanning: %s\n" "$DUMP"
printf "  Size: %s\n" "$(du -h "$DUMP" | cut -f1)"

sha256sum "$DUMP" > "$DUMP.sha256"
printf "  sha256   -> %s\n" "$DUMP.sha256"

strings -n 6 "$DUMP" > "$DUMP.strings.txt"
printf "  strings  -> %s\n" "$DUMP.strings.txt"

hexdump -C "$DUMP" | head -n 64 > "$DUMP.hex.txt"
printf "  hexdump  -> %s\n" "$DUMP.hex.txt"

objdump -D -b binary -m i386 -M x86-64,addr=0 "$DUMP" 2>/dev/null | head -n 200 > "$DUMP.disasm.txt"
printf "  disasm   -> %s\n" "$DUMP.disasm.txt"

if [[ -n "$YARA_RULE" ]]; then
    yara -w "$YARA_RULE" "$DUMP" > "$DUMP.yara.txt" 2>/dev/null || true
    printf "  yara     -> %s\n" "$DUMP.yara.txt"
fi

n=0; for f in "$DUMP".*; do [ -f "$f" ] && n=$((n+1)); done 2>/dev/null
printf "\033[32m[SYNTROPY] Done. %d artifacts generated.\033[0m\n" "$n"
