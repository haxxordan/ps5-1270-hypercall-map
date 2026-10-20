# The PS5 Hypervisor Interface on Firmware 12.70: A Complete Hypercall Map

**Author:** Daniel Walker ([@haxxordan](https://github.com/haxxordan)), independent security researcher
**Date:** October 2026
**Subject:** PlayStation 5 kernel, firmware 12.70

## Summary

The public documentation of the PS5 hypervisor interface — the
[psdevwiki hypercall list](https://www.psdevwiki.com/ps5/Hypervisor) — covers
17 hypercalls (0x0–0x10). Static analysis of the firmware 12.70 kernel shows
the real interface is larger: **25 hypercalls** with guest-side call sites,
including **13 that are not publicly documented** (0x12–0x15, 0x1b–0x20,
0x26–0x28).

This document is a complete map of that interface as of firmware 12.70: the
calling convention, every hypercall number with its wrapper and callers, the
argument signature of `STARTUP_MP` (the hypercall at the center of the public
Byepervisor Reborn hypervisor exploit), a structural identification of
hypercall 0x1f as the probable third `SET_CPUID` variant, and a subsystem
identification of the heavily-used 0x14/0x15 pair as a hypervisor-mediated
hardware event-channel service.

All results are from static analysis of a kernel `.text` dump taken from my
own console. Inferences are labeled as inferences; anything that requires
runtime confirmation is called out as such.

## Method

1. Dumped the kernel `.text` segment (13,959,168 bytes) from my own
   jailbroken PS5 running firmware 12.70.
2. Located every `VMMCALL` instruction (0F 01 D9) in the image and
   disassembled the surrounding code with objdump. Found 33 call sites:
   24 small wrapper functions plus 9 inline sites belonging to one batch
   function.
3. For each wrapper, extracted the hypercall number (loaded into EAX) and
   the argument shuffle; for each hypercall, enumerated all in-kernel
   callers by cross-reference.
4. Disassembled the caller functions of the undocumented hypercalls to
   recover argument shapes, sub-command sets, and subsystem structure.

All offsets below are file offsets into the kernel `.text` image
(kernel VA − KERNEL_TEXT).

## Calling convention (confirmed)

- Hypercall number in **EAX**
- Arguments in **EBX, ECX, EDX, ESI, EDI** (32-bit halves)
- Result returned in **EAX**
- Each hypercall has a small wrapper of the form:
  `push rbp; mov rsp,rbp; [argument shuffles]; mov $nr,%eax; vmmcall; pop rbp; ret`

## The map

| # | Name | Status | Callers in kernel |
|---|---|---|---|
| 0x4 | SET_CPUID_PS4 | documented | 2 |
| 0x5 | SET_CPUID_PPR | documented | 1 |
| 0x6 | IOMMU_SET_GUEST_BUFFERS | documented | 2 |
| 0x7 | IOMMU_ENABLE_DEVICE | documented | 2 |
| 0x8 | IOMMU_BIND_PASID | documented | 2 |
| 0x9 | IOMMU_UNBIND_PASID | documented | 1 |
| 0xa | IOMMU_CHECK_CMD_COMPLETION | documented | 7 |
| 0xb | IOMMU_CHECK_EVLOG_REGS | documented | 4 |
| 0xc | IOMMU_READ_DEVICE_TABLE | documented | 0 |
| 0xd | GET_TMR_VIOLATION_ERROR | documented | 9 inline sites (batch, subindex 0–7 in EBX) |
| 0xf | STARTUP_MP | documented | 2 |
| 0x10 | DISABLE_STARTUP_MP | documented | 2 |
| 0x12 | — | **undocumented** | inline site in a PCI-config-shaped function |
| 0x13 | — | **undocumented** | 1 |
| 0x14 | event-object register/map (inferred) | **undocumented** | 5 |
| 0x15 | event-object enable/state-change (inferred) | **undocumented** | 10 |
| 0x1b | — | **undocumented** | 0 (wrapper only) |
| 0x1c | — | **undocumented** | 0 (wrapper only) |
| 0x1d | — | **undocumented** | 0 (wrapper only) |
| 0x1e | — | **undocumented** | 0 (wrapper only) |
| 0x1f | SET_CPUID_PS5 (inferred) | **undocumented** | 3 |
| 0x20 | — | **undocumented** | 0 (wrapper only) |
| 0x26 | — | **undocumented** | 0 (wrapper only) |
| 0x27 | — | **undocumented** | 0 (wrapper only) |
| 0x28 | — | **undocumented** | 0 (wrapper only) |

Not present as immediates anywhere in `.text`: 0x0, 0x1, 0x2, 0x3, 0x11,
0xe (VMCLOSURE_INVOCATION). They may be invoked with the number computed in
a register, or not called from this code path.

Eight hypercalls (0x1b, 0x1c, 0x1d, 0x1e, 0x20, 0x26, 0x27, 0x28) have
compiled wrappers but **zero in-kernel callers** — reserved, debug, or
conditionally-compiled surface that ships in the retail kernel.

## Finding 1: STARTUP_MP (0xf) argument signature

`STARTUP_MP` is the hypercall whose insecure S3-resume handling the public
[Byepervisor Reborn](https://github.com/PS5Dev/Byepervisor-Reborn) exploit
abuses. Its wrapper (file offset 0xc9dfb0) and both callers agree on the
signature:

```
STARTUP_MP(cpu_index, wakeup_struct_ptr, cr3)
```

- arg1 = CPU index (a byte from a per-CPU table)
- arg2 = pointer to a per-CPU wakeup/startup structure
- arg3 = CR3 (`mov %cr3,%rdx` immediately before the call)

The return value is checked at both call sites. Both callers live in large
CPU-bringup functions and follow the same shape: `DISABLE_STARTUP_MP` →
shared setup sequence → `STARTUP_MP`. Which of the two is boot-time AP
startup versus S3-resume AP re-startup cannot be determined from `.text`
alone; that distinction needs runtime context.

(My own contribution to Byepervisor Reborn — the firmware 12.70 support the
map was built alongside — is
[PR #12](https://github.com/PS5Dev/Byepervisor-Reborn/pull/12) in that
repository.)

## Finding 2: 0x1f is very likely the third SET_CPUID hypercall

The public list has a pair: 0x4 `SET_CPUID_PS4` and 0x5 `SET_CPUID_PPR`.
Hypercall 0x1f's principal caller sits in a CPU-bringup function that reads
a per-CPU state byte and branches three ways:

- state 0 → **0x1f** (no arguments), then sets MSR 0xc0000103 (TSC_AUX)
- state 1 → 0x4 (SET_CPUID_PS4)
- state 2 → 0x5 (SET_CPUID_PPR)

0x1f's other two callers also sit adjacent to SET_CPUID_PS4/PPR call sites.
Structurally, 0x1f fills the missing third slot in the CPU-personality
family — most plausibly **SET_CPUID_PS5**. Runtime confirmation (invoke and
read back CPUID leaves) is still outstanding.

## Finding 3: 0x14/0x15 are a hypervisor event-channel service

0x14 and 0x15 are the most-called undocumented hypercalls (5 and 10 call
sites). Both are sub-command dispatched:

- **0x14(subcmd, ptr[, val])** — always carries a payload pointer
- **0x15(subcmd)** — a bare sub-command selector

Observed sub-commands include 0x1, 0x6, 0x9 (one caller validates the index
against exactly this set), 0x12, 0x14, 0x16, 0x17, 0x19, 0x1a, 0x1e, 0x1f.

Caller analysis shows all 0x14/0x15 users funnel through one kernel-side
registration validator and type dispatcher into a single subsystem: an
interrupt-driven platform-device driver. Its attach path allocates an IRQ
resource and installs a handler that reads a 64-bit event ID from MMIO,
acknowledges it, sets pending bits, and wakes an interrupt thread; a
dispatcher demultiplexes 32 pending bits to per-event handlers.

The uniform call pattern across all three caller groups — 0x14 with a
payload pointer on registration paths, 0x15 on success/activation paths and
as the undo operation on failure paths — supports this reading:

- **0x14 = register/map an event object with the hypervisor**
- **0x15 = enable / state-change on that object**

In other words, the hypervisor mediates hardware event delivery to the
guest kernel: the driver demultiplexes hardware events, but the event
objects themselves are hypervisor-registered. (An earlier guess that this
subsystem is IOMMU-adjacent does not hold up — the driver's globals are
referenced only from its own region, with no cross-references from the
IOMMU code.)

## Limitations

- Static analysis of `.text` only: no symbols, no `.data`, no `.rodata`
  strings. The exact device behind the 0x14/0x15 event service cannot be
  named without its strings.
- 0x15's direction (enable vs. release) and 0x1f's identity as
  SET_CPUID_PS5 are strong structural inferences, not runtime-verified
  facts.
- A `.text` dump cannot show hypercalls invoked with computed numbers, so
  the map is a floor, not a ceiling, on the interface size.

## Related work

- [psdevwiki — PS5 Hypervisor](https://www.psdevwiki.com/ps5/Hypervisor)
  (the documented 17-hypercall list this map extends)
- [Byepervisor Reborn](https://github.com/PS5Dev/Byepervisor-Reborn) —
  public hypervisor exploit for 6.xx–13.60 via the S3-resume `STARTUP_MP`
  path; original bug by theflow0
- [PR #12 — Add firmware 12.70 support](https://github.com/PS5Dev/Byepervisor-Reborn/pull/12)
  (author's port of the exploit to 12.70)
