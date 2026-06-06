/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
 *
 * Cross-arch register-file shim for the uprobe programs (U-021).
 *
 * bpf2go cross-compiles sslsniff for amd64 AND arm64 from one build host,
 * but vmlinux.h is dumped from that host's BTF: an x86_64-dumped vmlinux.h
 * defines x86's struct pt_regs and NOT arm64's struct user_pt_regs, which
 * bpf_tracing.h's PT_REGS_PARM*/PT_REGS_RC cast the uprobe context to under
 * __TARGET_ARCH_arm64. The definition below is the arm64 UAPI register file
 * (uapi/asm/ptrace.h) — stable kernel ABI, so defining it here is safe.
 *
 * Building the objects on an arm64 host instead? Its vmlinux.h already
 * defines the struct: pass -DPROBECTL_VMLINUX_HAS_USER_PT_REGS to skip this
 * shim (the x86 leg would then need the mirrored treatment for x86's
 * struct pt_regs — the supported object-build hosts are x86_64, which is
 * what CI and the release pipeline use).
 */
#ifndef PROBECTL_BPF_ARCH_COMPAT_H
#define PROBECTL_BPF_ARCH_COMPAT_H

#if defined(__TARGET_ARCH_arm64) && !defined(PROBECTL_VMLINUX_HAS_USER_PT_REGS)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

#endif /* PROBECTL_BPF_ARCH_COMPAT_H */
