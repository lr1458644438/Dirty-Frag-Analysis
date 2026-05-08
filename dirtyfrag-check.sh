#!/bin/bash
# Dirty Frag 检测脚本
# CVE-2026-43284 (xfrm-ESP) / CVE-2026-43500 (RxRPC)

echo "============================================"
echo "  Dirty Frag Vulnerability Check"
echo "  CVE-2026-43284 / CVE-2026-43500"
echo "============================================"
echo ""

VULN=0

# 检查 esp4 模块
if lsmod 2>/dev/null | grep -q "^esp4 "; then
    echo "[!] VULNERABLE: esp4 module is loaded"
    VULN=1
elif modprobe -n esp4 2>/dev/null; then
    echo "[!] VULNERABLE: esp4 module is available (can be loaded)"
    VULN=1
else
    echo "[+] OK: esp4 module not available"
fi

# 检查 esp6 模块
if lsmod 2>/dev/null | grep -q "^esp6 "; then
    echo "[!] VULNERABLE: esp6 module is loaded"
    VULN=1
elif modprobe -n esp6 2>/dev/null; then
    echo "[!] VULNERABLE: esp6 module is available (can be loaded)"
    VULN=1
else
    echo "[+] OK: esp6 module not available"
fi

# 检查 rxrpc 模块
if lsmod 2>/dev/null | grep -q "^rxrpc "; then
    echo "[!] VULNERABLE: rxrpc module is loaded"
    VULN=1
elif modprobe -n rxrpc 2>/dev/null; then
    echo "[!] VULNERABLE: rxrpc module is available (can be loaded)"
    VULN=1
else
    echo "[+] OK: rxrpc module not available"
fi

# 检查 user namespace
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
    if [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" = "1" ]; then
        echo "[!] VULNERABLE: unprivileged user namespace creation is enabled"
        VULN=1
    else
        echo "[+] OK: unprivileged user namespace creation is disabled"
    fi
fi

# 检查缓解措施
if [ -f /etc/modprobe.d/dirtyfrag.conf ]; then
    echo "[+] MITIGATION: /etc/modprobe.d/dirtyfrag.conf exists"
else
    echo "[!] NO MITIGATION: /etc/modprobe.d/dirtyfrag.conf not found"
fi

echo ""
if [ $VULN -eq 1 ]; then
    echo "[!!!] SYSTEM IS VULNERABLE TO DIRTY FRAG"
    echo ""
    echo "Mitigation:"
    echo "  sh -c 'printf \"install esp4 /bin/false\\ninstall esp6 /bin/false\\ninstall rxrpc /bin/false\\n\" > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches'"
else
    echo "[+] System appears to be protected"
fi
