# psdevwiki contribution draft — PS5 Hypervisor page additions

Source: firmware 12.70 kernel .text analysis (see README.md in this package).
Rows below cover the hypercalls present in 12.70 but missing from the
current public list. Suggested descriptions are conservative: inferred
semantics are marked as such.

| Hypercall # | Proposed name / description |
|---|---|
| 0x12 | Unknown. Single inline call site inside a function issuing PCI-config-space-shaped accesses (offsets 0xb5/0xbb) around device handles. Possibly PCI/IOMMU-adjacent. |
| 0x13 | Unknown. One in-kernel caller. Takes (subcmd/arg) shape via wrapper. |
| 0x14 | Register/map hypervisor event object (inferred). Signature (subcmd, ptr[, val]); sub-commands observed: 0x1, 0x6, 0x9, 0x12, 0x1e, 0x1f. Part of the HV event-channel service with 0x15. |
| 0x15 | Enable/state-change hypervisor event object (inferred). Signature (subcmd); sub-commands observed: 0x1, 0x6, 0x9, 0x12, 0x14, 0x16, 0x17, 0x19, 0x1a. Called on activation paths and as undo on registration failure. |
| 0x1b | Unknown. Wrapper exists in kernel; no in-kernel callers on 12.70. Widest argument shuffle of the unknown set (6+ args). |
| 0x1c | Unknown. Wrapper exists; no in-kernel callers. Takes no arguments. |
| 0x1d | Unknown. Wrapper exists; no in-kernel callers. Takes 2 pass-through arguments. |
| 0x1e | Unknown. Wrapper exists; no in-kernel callers. Takes no arguments. |
| 0x1f | SET_CPUID_PS5 (inferred). Third member of the SET_CPUID family next to 0x4 (PS4) and 0x5 (PPR): its caller branches on a per-CPU state byte — state 0 → 0x1f, state 1 → 0x4, state 2 → 0x5 — then sets MSR 0xc0000103 (TSC_AUX). Takes no arguments. Runtime confirmation pending. |
| 0x20 | Unknown. Wrapper exists; no in-kernel callers. Takes no arguments. |
| 0x26 | Unknown. Wrapper exists; no in-kernel callers. Packs 5 small integers into EBX/ECX/EDX. |
| 0x27 | Unknown. Wrapper exists; no in-kernel callers. Takes 1 small integer argument. |
| 0x28 | Unknown. Wrapper exists; no in-kernel callers. Echo/validate shape: writes results only to caller-supplied scratch pointers. |

## Also worth adding to the STARTUP_MP (0xf) entry

Argument signature recovered from the wrapper and both callers on 12.70:
`STARTUP_MP(cpu_index, wakeup_struct_ptr, cr3)` — arg3 is loaded directly
from CR3 immediately before the VMMCALL; the return value is error-checked
at both call sites.
