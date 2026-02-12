# Additional Detection Vectors (H1-H10)
# hyper-reV Software DMA - Extended Analysis
# Date: 2026-02-08

## Summary
# Existing: A1-A11(CPU), B1-B5(EPT/HV), C1-C5(Boot), D1-D3(Network), E1-E5(PCIe), F1-F3(Behavioral), G1-G3(Fault)
# New: H1-H10 (hyper-reV specific + 2025 anti-cheat evolution)

---

## H1. UEFI Boot Entry / NVRAM Variable Enumeration
# Risk: ★★★☆☆
# Description: bcdedit /enum all or UEFI NVRAM variable scan reveals custom boot entries.
#   Our stealth mode creates a boot entry pointing to \efi\hyper-rev\bootx64.efi.
#   Anti-cheat (Ring 0) can call NtEnumerateBootEntries or read UEFI variables to find non-standard entries.
#   Even after cleanup, NVRAM residue may persist.
# Impact on hyper-reV:
#   - bcdedit /copy {bootmgr} creates a visible entry
#   - Entry points to non-Microsoft path = suspicious
#   - NVRAM variables persist across reboots
# Mitigation:
#   Option A: USB boot (zero NVRAM footprint on internal disk)
#   Option B: Set entry as default, then delete entry after boot via hyperv-attachment cleanup
#   Option C: One-time boot via UEFI firmware boot menu (no persistent NVRAM entry)
# Status: ⚠️ Requires operational mitigation

## H2. EFI Memory Map Anomaly (EfiRuntimeServicesData Allocation)
# Risk: ★★☆☆☆
# Description: uefi-boot allocates ~1024 pages of EfiRuntimeServicesData for hyperv-attachment heap.
#   OS preserves EfiRuntimeServicesData after ExitBootServices().
#   Anti-cheat could enumerate EFI memory map via NtQuerySystemInformation or direct ACPI table parsing.
#   Unusual large EfiRuntimeServicesData blocks without corresponding RuntimeServices driver = suspicious.
# Impact on hyper-reV:
#   - Heap allocation (1024 4KB pages = 4MB) of EfiRuntimeServicesData is visible in OS memory map
#   - Normal systems have small EfiRuntimeServicesData for UEFI runtime services
#   - 4MB extra block stands out statistically
# Mitigation:
#   Hyper-V itself uses large EfiRuntimeServicesData allocations, so our block blends in.
#   Alternative: Use EfiACPIMemoryNVS or allocate as EfiBootServicesData (gets reclaimed, but we
#   copy to Hyper-V address space before ExitBootServices anyway).
#   Current code copies to Hyper-V's virtual space (PML4[255]) so physical pages could be freed.
# Status: ⚠️ Low risk, needs analysis of typical Hyper-V memory map

## H3. NIC Hardware Statistics Counter Discrepancy
# Risk: ★★★☆☆
# Description: Intel NIC maintains hardware TX/RX packet counters in MMIO statistics registers.
#   Ring -1 MMIO TX creates packets counted by hardware but NOT by Guest OS NDIS counters.
#   Anti-cheat could compare:
#     - NIC hardware stats (via DeviceIoControl or direct register read) 
#     - OS NDIS performance counters
#   Discrepancy = phantom traffic = DMA/Ring-1 activity
# Impact on hyper-reV:
#   - Every DMA response packet increments hardware TX counter
#   - Guest OS never sees these packets (bypassed network stack)
#   - Delta = exact count of our covert packets
# Mitigation:
#   Option A: After each TX, read hardware stats registers and adjust (write back decremented value)
#     Intel I219: MMIO statistics registers are R/C (Read and Clear) or R/W depending on register
#     TPT (0x40D4) = Total Packets Transmitted - could be reset
#   Option B: Use TX packets that are "legitimate" - piggyback on existing guest traffic descriptors
#   Option C: Monitor Guest's stats query patterns and intercept via EPT on stats register access
#     (but this reintroduces EPT hooks which we eliminated)
# Status: ⚠️ Needs implementation - stats register manipulation in NIC MMIO TX code

## H4. VMEXIT Processing Latency Distribution Shift
# Risk: ★★☆☆☆
# Description: Our VMEXIT handler runs process_pending() on every exit to poll NIC for incoming DMA commands.
#   This adds overhead to ALL VMEXITs, not just specific ones.
#   Anti-cheat can measure VMEXIT latency distribution via:
#     rdtsc; cpuid; rdtsc (triggers VMEXIT, measures round-trip)
#   Statistical distribution shift (mean + variance increase) = foreign VMEXIT handler code
# Impact on hyper-reV:
#   - Normal Hyper-V VMEXIT: ~1-3 microseconds
#   - With process_pending() polling: adds NIC register reads per VMEXIT
#   - If NIC has no pending data: 2-3 register reads (~100ns each) = ~300ns overhead
#   - Statistically detectable over thousands of samples
# Mitigation:
#   Option A: Only poll NIC on timer-based intervals (e.g., every 1000th VMEXIT) instead of every VMEXIT
#     Reduces avg overhead to ~0.3ns per VMEXIT (undetectable)
#     Trade-off: higher DMA command latency (~1-5ms)
#   Option B: Use NIC interrupt (MSI-X) to trigger processing instead of polling
#     Zero overhead on non-NIC VMEXITs
#     Complex: need to intercept NIC interrupt delivery
#   Option C: Rate-limit polling based on rdtsc delta since last poll
# Status: ⚠️ Should implement Option A (timer-based polling)

## H5. NIC TX Descriptor Ring Contention
# Risk: ★★☆☆☆
# Description: Guest NIC driver (e1000e/igb) and Ring -1 both manipulate TX descriptor ring.
#   Even though we only write during VMEXIT (guest paused), race conditions possible:
#   - Guest queues TX descriptors, sets TDT (Tail)
#   - VMEXIT fires for unrelated reason
#   - We write our descriptor, advance TDT
#   - Guest resumes, its TDT write now points to wrong offset
#   - NIC driver detects "TX hang" or descriptor completion errors
# Impact on hyper-reV:
#   - Guest NIC driver logs errors in Event Viewer (System log)
#   - Anti-cheat monitors system event logs for NIC anomalies
#   - Repeated TX hangs correlate with cheat activity
# Mitigation:
#   Current design: use separate TX queue (Intel NIC has 2-4 TX queues)
#   Queue 0 = Guest, Queue 1 = Ring -1 covert channel
#   No contention possible with separate queues
# Status: ✅ Resolved by design (separate TX queue)

## H6. Physical Memory Signature Scanning
# Risk: ★☆☆☆☆
# Description: Anti-cheat with Ring 0 access could scan physical memory ranges for:
#   - hyperv-attachment code patterns/strings
#   - Known VMEXIT handler hook signatures
#   - PE headers in unexpected physical regions
# Impact on hyper-reV:
#   - hyperv-attachment lives in Hyper-V address space (PML4[255] = physical memory access)
#   - From Guest Ring 0: physical memory is accessed through EPT
#   - Hyper-V's EPT does NOT map its own code/data into Guest physical view
#   - Guest physically CANNOT read hypervisor memory regions
# Mitigation: None needed - architectural isolation via EPT
# Status: ✅ Resolved by Hyper-V EPT isolation

## H7. Secure Boot / Code Signing Enforcement
# Risk: ★★★☆☆  
# Description: Secure Boot verifies digital signatures of all EFI binaries.
#   Our hyper-rev bootx64.efi is NOT signed by Microsoft.
#   If Secure Boot enabled: our EFI binary won't load.
#   If Secure Boot disabled to allow our binary: anti-cheat detects Secure Boot off.
#   Vanguard (2025) requires Secure Boot ON.
# Impact on hyper-reV:
#   - Current: requires Secure Boot OFF (or custom keys enrolled)
#   - Vanguard/FACEIT/EAC increasingly require Secure Boot ON
#   - Arc Raiders uses EAC → likely enforces Secure Boot in future
# Mitigation:
#   Option A: Enroll custom Secure Boot keys (MOK - Machine Owner Key)
#     Self-sign hyper-rev.efi, add key to MOK database
#     Secure Boot stays ON, our binary loads
#     Risk: Anti-cheat could enumerate MOK database for non-standard keys
#   Option B: shim-based approach (sign with leaked/vulnerable keys)
#     High risk, keys get revoked via DBX updates
#   Option C: Boot from USB with Secure Boot temporarily disabled, re-enable after
#     Not viable for games requiring Secure Boot ON
# Status: ⚠️ Significant - needs MOK enrollment or architectural change

## H8. IOMMU / Pre-Boot DMA Protection Enforcement (Vanguard 2025)
# Risk: ★☆☆☆☆ (for software DMA)
# Description: Vanguard (Dec 2025) discovered motherboard IOMMU early-init vulnerabilities.
#   CVE-2025-11901, CVE-2025-14302~14304.
#   Now enforces: IOMMU enabled + Pre-Boot DMA Protection + BIOS firmware up-to-date.
#   Blocks game launch if system appears vulnerable to early-boot DMA injection.
# Impact on hyper-reV:
#   - We are SOFTWARE DMA, not physical DMA card
#   - No PCIe device to block via IOMMU
#   - IOMMU restrictions target physical DMA cards, not hypervisor-level access
#   - Having IOMMU ON is actually fine for us
# Mitigation: None needed - we benefit from IOMMU being enabled (looks like secure system)
# Status: ✅ N/A - software DMA unaffected by IOMMU enforcement

## H9. VBS Enclave / Secure Kernel Future Threat
# Risk: ★★☆☆☆ (future, not current)
# Description: Samuel Tulach (Dec 2024) demonstrated VBS enclaves for anti-cheat.
#   Game logic runs in VTL1 (Secure World) which even Ring -1 hypervisor hooks can't easily read.
#   Anti-cheat could move critical game state (player positions, health) to VBS enclave.
#   Hyper-V parasitic approach (our design) can intercept VTL transitions but reading VTL1 memory
#   requires additional complexity.
# Impact on hyper-reV:
#   - Current games: NOT using VBS enclaves
#   - Future possibility: game data in VTL1 would require VTL1 memory access
#   - Tulach showed even VBS can be bypassed from firmware/bootkit level
#   - Our position (inside Hyper-V) is actually BETTER than external DMA for VBS access
# Mitigation: 
#   Our Hyper-V hook position can intercept ShvlpVtlReturn (VTL1→VTL0 transitions)
#   and read Secure Kernel memory by mapping its physical pages
#   (Tulach demonstrated this exact technique in his bootkit paper)
# Status: ⚠️ Future concern - but our architecture is well-positioned

## H10. NIC A/B Functionality Testing (Vanguard/EAC 2024-2025)
# Risk: ★☆☆☆☆ (for real NIC)
# Description: Per isdmadead.com timeline, Vanguard/EAC now perform A/B functionality tests:
#   - Send fake packets to NIC and verify response
#   - Test if NIC is real vs FPGA-spoofed device
#   - "is_current_nic" check - only allow 1 active NIC
#   - Test WiFi/Audio/XHCI device functionality via fake data
# Impact on hyper-reV:
#   - We use the REAL system NIC, not a spoofed FPGA device
#   - A/B tests target fake PCIe devices, not real NICs
#   - "is_current_nic" blocks dual-NIC setups (physical DMA uses 2nd NIC)
#   - We use the SAME NIC the game uses → passes is_current_nic
# Mitigation: None needed - real NIC passes all functionality tests
# Status: ✅ N/A - real NIC, not spoofed device


## ============================================
## GRAND TOTAL DETECTION VECTOR STATUS
## ============================================
## 
## Original 31 vectors (A1-G3): 30 resolved, 1 remaining (F1 behavioral)
## New 10 vectors (H1-H10):
##   H1 NVRAM/Boot Entry:     ⚠️ Needs operational mitigation (USB boot or one-time UEFI menu)
##   H2 EFI Memory Map:       ⚠️ Low risk (Hyper-V has similar allocations)
##   H3 NIC Stats Counter:    ⚠️ Needs stats register manipulation code
##   H4 VMEXIT Latency:       ⚠️ Should implement timer-based polling
##   H5 TX Ring Contention:   ✅ Resolved (separate TX queue)
##   H6 Physical Mem Scan:    ✅ Resolved (EPT isolation)
##   H7 Secure Boot:          ⚠️ Significant - MOK enrollment needed
##   H8 IOMMU/Pre-Boot DMA:   ✅ N/A (software DMA)
##   H9 VBS Enclave:          ⚠️ Future concern only
##   H10 NIC A/B Testing:     ✅ N/A (real NIC)
##
## FINAL: 34/41 fully resolved, 7/41 need mitigation
##   Critical (must fix):  H7 (Secure Boot), H3 (NIC stats)
##   Should fix:           H4 (VMEXIT latency), H1 (NVRAM)
##   Low priority:         H2 (EFI memory map), H9 (VBS future)
##   User-dependent:       F1 (behavioral analysis)
