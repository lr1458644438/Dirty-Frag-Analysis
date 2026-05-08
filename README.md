# Dirty Frag 深度技术分析

> CVE-2026-43284 (xfrm-ESP) / CVE-2026-43500 (RxRPC)
>
> Linux 内核本地提权漏洞 — PoC 逆向 · Shellcode 拆解 · 补丁原理 · 检测脚本

## 漏洞概述

Dirty Frag 通过链式利用 `xfrm-ESP Page-Cache Write` 和 `RxRPC Page-Cache Write` 两个独立漏洞，在几乎所有主流 Linux 发行版上实现本地普通用户到 root 的提权。

- **确定性逻辑漏洞**，无竞态条件，100% 成功率
- **完全绕过 Copy Fail 缓解措施**
- 影响范围：2017 年至今几乎所有 Linux 内核

## 文件说明

| 文件 | 说明 |
|------|------|
| [dirtyfrag-analysis.md](dirtyfrag-analysis.md) | 完整技术分析文章 |
| [dirtyfrag-check.sh](dirtyfrag-check.sh) | 一键检测脚本（esp4/esp6 + rxrpc） |

## 快速检测

```bash
# 一行命令快速检测
lsmod | grep -qE "esp4|rxrpc" && echo "[!] 存在风险" || echo "[+] 安全"

# 或使用完整检测脚本
bash dirtyfrag-check.sh
```

## 临时修复

```bash
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches"
```

> ⚠️ 修复前请确认系统未使用 IPsec VPN / SD-WAN / K8s pod 间 IPsec 加密

## 实战验证

```
OS:      Ubuntu 22.04.5 LTS
Kernel:  5.15.0-171-generic
User:    ubuntu (uid=1000) → root (uid=0)
Variant: xfrm-ESP Page-Cache Write
Time:    ~8 seconds
```

## 致谢

- 漏洞发现者：[Hyunwoo Kim (@v4bel)](https://x.com/v4bel)
- [Dirty Frag 官方仓库](https://github.com/V4bel/dirtyfrag)

## 免责声明

本文仅供安全研究和学习交流，请勿用于未授权的系统测试。

---

**Author:** Bomb

**WeChat:** AK7777177（安全研究交流、漏洞分析合作）
