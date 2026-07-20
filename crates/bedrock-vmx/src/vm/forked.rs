// SPDX-License-Identifier: GPL-2.0

//! ForkedVm - Copy-on-write VM derived from a parent.
//!
//! This module provides `ForkedVm`, which shares its parent's memory but
//! allocates new pages on write using copy-on-write semantics.

#[cfg(not(feature = "cargo"))]
use super::super::prelude::*;
#[cfg(feature = "cargo")]
use crate::prelude::*;

use super::{ForkableVm, ParentVm};
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(feature = "cargo"))]
use super::super::exits::raise_preempt_vector;
#[cfg(feature = "cargo")]
use crate::exits::raise_preempt_vector;

#[cfg(not(feature = "cargo"))]
use super::super::dr_watch::ArmResult;
#[cfg(feature = "cargo")]
use crate::dr_watch::ArmResult;

const PAGE_SIZE: usize = 4096;

// Arm-then-cull tuning for EPT write-watchpoints lives in ApicState
// (watchpoint_cull_epochs / watchpoint_cull_cap), set from the
// BEDROCK_WATCHPOINT_CULL_EPOCHS / BEDROCK_WATCHPOINT_CULL_CAP env knobs so it
// can be tuned on-box without a rebuild. On a single vCPU one thread runs a
// whole quantum, so a genuinely-shared page looks single-writer for many faults
// before another thread is scheduled. So the PRIMARY cull signal is surviving
// `cull_epochs` observed userspace thread switches still single-writer; the
// `cull_cap` fault count is only a backstop for a page that never spans a switch
// (e.g. a single-threaded phase). A too-low cap culls shared spin-loop pages
// before a second thread writes them (a false negative for bug 7); a too-high
// cap makes no-switch phases crawl. Defaults 2 / 256.

/// Error type for ForkedVm creation.
#[derive(Debug)]
pub enum ForkedVmError<E> {
    /// Parent VM has children and cannot be forked.
    ParentHasChildren,
    /// EPT clone failed.
    EptClone(E),
    /// VMCS allocation failed.
    VmcsAlloc,
    /// VmState creation failed.
    VmState(VmStateError<E>),
}

/// A forked VM using copy-on-write memory.
///
/// `ForkedVm` shares its parent's memory but allocates new pages on write.
/// The EPT is cloned from parent with R+X (no write) permissions, so
/// writes cause EPT violations that trigger COW page allocation.
///
/// # Parent Relationship
///
/// ForkedVm holds a trait object pointer to the parent VM. When reading
/// non-COW pages, it calls through to the parent's `ParentVm` implementation,
/// which may recursively check its own COW pages (for nested forks) before
/// reaching the root memory.
///
/// The parent must outlive the ForkedVm, which is enforced by the children
/// counter on the parent. When a ForkedVm is created, the parent's
/// children_count is incremented. When dropped, children_count is decremented.
///
/// # Type Parameters
///
/// * `V` - The VMCS type, must implement `VirtualMachineControlStructure`
/// * `P` - The page type for COW pages
/// * `I` - The instruction counter type
#[repr(C)]
pub struct ForkedVm<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> {
    /// VM state (VMCS, registers, devices, etc.). Boxed to reduce stack usage.
    pub state: VmStateBox<V, I>,

    /// Copy-on-write pages owned by this VM.
    pub cow_pages: CowPageMap<P>,

    /// Per-page EPT write-watchpoint classification (arm-then-cull). Populated
    /// only when watchpoints are enabled; empty and unused otherwise.
    pub watchpoint_class: WatchpointClassMap,

    /// Last userspace thread id (guest FS_BASE) seen at a watchpoint fault.
    wp_last_tid: u64,

    /// Count of observed userspace thread switches (bumped when the FS_BASE at a
    /// CPL 3 watchpoint fault differs from `wp_last_tid`). Drives the cull epoch.
    /// The arm-then-cull diagnostic counters (faults/armed/culled/confirmed/
    /// preempts) and this epoch live in `exit_stats` (AllExitStats.wp_*), which
    /// reaches userspace via GET_EXIT_STATS rather than dmesg.
    wp_switch_epoch: u32,

    /// Parent VM for reading non-COW pages (type-erased trait object).
    parent: *const dyn ParentVm,

    /// Number of child ForkedVms derived from this VM.
    /// Uses AtomicUsize for interior mutability (remove_child called via &self).
    children_count: AtomicUsize,
}

// SAFETY: ForkedVm can be sent between threads. The parent pointer is
// safe because the parent VM's memory is stable (children counter prevents
// the parent from being modified/dropped while children exist).
unsafe impl<V: VirtualMachineControlStructure + Send, P: Page + Send, I: InstructionCounter + Send>
    Send for ForkedVm<V, P, I>
{
}

// SAFETY: ForkedVm can be shared between threads for read access.
unsafe impl<V: VirtualMachineControlStructure + Sync, P: Page + Sync, I: InstructionCounter + Sync>
    Sync for ForkedVm<V, P, I>
{
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> ForkedVm<V, P, I> {
    /// Create a new ForkedVm from a parent VM.
    ///
    /// This method:
    /// 1. Increments the parent's children count
    /// 2. Clones the parent's EPT with R+X (no write) permissions for COW
    /// 3. Creates a new VmState by copying parent's device/MSR/register state
    /// 4. Creates an empty COW page map
    /// 5. Stores a trait object pointer to the parent for COW chain traversal
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent VM (RootVm or another ForkedVm)
    /// * `machine` - Machine for allocating pages and VMCS
    /// * `allocator` - Frame allocator for EPT cloning and COW pages
    /// * `exit_handler_rip` - Address of the VM exit handler
    /// * `instruction_counter` - Instruction counter for this VM
    ///
    /// # Type Parameters
    ///
    /// * `A` - Frame allocator type
    /// * `Parent` - Parent VM type (implements ForkableVm)
    #[inline(never)]
    pub fn new<
        A: FrameAllocator<Frame = V::P> + CowAllocator<P>,
        Parent: ForkableVm<V, I> + 'static,
    >(
        parent: &Parent,
        machine: &V::M,
        allocator: &mut A,
        exit_handler_rip: u64,
        instruction_counter: I,
    ) -> Result<Self, ForkedVmError<A::Error>>
    where
        V::P: Into<P>,
        V::M: Machine,
    {
        // Increment parent's children count (atomic operation)
        parent.add_child();

        Self::new_internal(
            parent,
            machine,
            allocator,
            exit_handler_rip,
            instruction_counter,
        )
    }

    /// Create a new ForkedVm from a parent VM whose children_count was already incremented.
    ///
    /// This is the parallel-fork-safe variant of `new()`. The caller is responsible for:
    /// 1. Incrementing the parent's children_count BEFORE calling this method
    /// 2. Decrementing children_count if this method returns an error
    ///
    /// This design allows the caller to increment children_count while holding a lock,
    /// release the lock, then call this method for the expensive work. Multiple threads
    /// can call this method concurrently for the same parent since all operations are
    /// read-only (the parent cannot run while children_count > 0).
    ///
    /// # Safety
    ///
    /// Caller must have already called `parent.add_child()` before calling this method.
    /// If this method returns an error, caller must call `parent.remove_child()`.
    #[inline(never)]
    pub fn new_with_incremented_parent<
        A: FrameAllocator<Frame = V::P> + CowAllocator<P>,
        Parent: ForkableVm<V, I> + 'static,
    >(
        parent: &Parent,
        machine: &V::M,
        allocator: &mut A,
        exit_handler_rip: u64,
        instruction_counter: I,
    ) -> Result<Self, ForkedVmError<A::Error>>
    where
        V::P: Into<P>,
        V::M: Machine,
    {
        // Note: caller has already incremented parent's children_count
        Self::new_internal(
            parent,
            machine,
            allocator,
            exit_handler_rip,
            instruction_counter,
        )
    }

    /// Internal constructor shared by `new` and `new_with_incremented_parent`.
    #[inline(never)]
    fn new_internal<
        A: FrameAllocator<Frame = V::P> + CowAllocator<P>,
        Parent: ForkableVm<V, I> + 'static,
    >(
        parent: &Parent,
        machine: &V::M,
        allocator: &mut A,
        exit_handler_rip: u64,
        instruction_counter: I,
    ) -> Result<Self, ForkedVmError<A::Error>>
    where
        V::P: Into<P>,
        V::M: Machine,
    {
        // Clone parent's EPT with R+X permissions (COW setup)
        let ept: EptPageTable<V::P> = parent
            .vm_state()
            .ept
            .clone_for_fork(allocator)
            .map_err(ForkedVmError::EptClone)?;

        // Create a new VMCS for this forked VM
        let vmcs = V::new(machine).map_err(|_| ForkedVmError::VmcsAlloc)?;

        // Create VmState by copying from parent
        let state = VmState::new_for_fork::<A, I>(
            vmcs,
            ept,
            parent.vm_state(),
            machine,
            exit_handler_rip,
            instruction_counter,
        )
        .map_err(ForkedVmError::VmState)?;

        // Store trait object pointer to parent for COW chain traversal.
        // Parent must outlive this ForkedVm, enforced by children_count.
        let parent_ptr: *const dyn ParentVm = parent as &dyn ParentVm;

        let mut forked_vm = Self {
            state: box_vm_state(state),
            cow_pages: CowPageMap::<P>::new(),
            watchpoint_class: WatchpointClassMap::new(),
            wp_last_tid: 0,
            wp_switch_epoch: 0,
            parent: parent_ptr,
            children_count: AtomicUsize::new(0),
        };

        // Feedback buffers need no special handling at fork: their pages are
        // copied-on-write lazily through the normal EPT write-fault path
        // (`handle_cow_fault`) when the guest writes them. When userspace maps
        // a buffer, `cow_feedback_buffer_for_mapping` COWs its pages so the
        // mapping stays coherent with subsequent guest writes.

        // Pre-COW the I/O channel shared page if registered. Without this
        // any HYPERCALL_IO_GET_REQUEST that fires on the fork would hit
        // write_guest_memory's "page not COW'd yet" error path and the
        // request would never reach the guest module.
        forked_vm.pre_cow_io_channel_page(allocator);

        Ok(forked_vm)
    }

    /// Get a reference to the COW pages.
    pub fn cow_pages(&self) -> &CowPageMap<P> {
        &self.cow_pages
    }

    /// Get a mutable reference to the COW pages.
    pub fn cow_pages_mut(&mut self) -> &mut CowPageMap<P> {
        &mut self.cow_pages
    }

    /// Remap a watched page to RWX and flush the affected EPT mapping so the
    /// pending write can proceed. Shared by the let-through-and-step and cull
    /// paths. Returns false (with a log) if the remap fails.
    fn wp_remap_rwx<A: CowAllocator<P>>(
        &mut self,
        page_gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        allocator: &mut A,
    ) -> bool
    where
        V::M: Machine,
    {
        if let Err(_e) = self.state.ept.remap_4k(
            allocator,
            page_gpa,
            hpa,
            EptPermissions::READ_WRITE_EXECUTE,
            EptMemoryType::WriteBack,
        ) {
            log_err!(
                "watchpoint: failed to grant write for GPA {:#x}\n",
                page_gpa.as_u64()
            );
            return false;
        }
        let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());
        true
    }

    /// Let a watched write through and LEAVE the page writable (RWX): the next
    /// write to it will not fault until the batch re-arm (`rearm_watchpoints`)
    /// re-protects it to R+E. This is the sampling protocol: one fault per page
    /// per re-arm window instead of one fault (plus an MTF step and two INVEPTs)
    /// per write.
    fn wp_grant_and_leave<A: CowAllocator<P>>(
        &mut self,
        page_gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        allocator: &mut A,
    ) -> Option<ExitHandlerResult>
    where
        V::M: Machine,
    {
        if !self.wp_remap_rwx(page_gpa, hpa, allocator) {
            return None;
        }
        Some(ExitHandlerResult::Continue)
    }

    /// Cull a single-writer watched page: grant write permanently and drop its
    /// classification record, so it stops faulting for good. Removing the record
    /// is REQUIRED under sampling: the batch re-arm (`rearm_watchpoints`) walks
    /// the classification map and re-protects every page in it, so a leftover
    /// record would re-arm a culled page every window and resurrect its cost.
    fn wp_cull<A: CowAllocator<P>>(
        &mut self,
        page_gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        allocator: &mut A,
    ) -> Option<ExitHandlerResult>
    where
        V::M: Machine,
    {
        if !self.wp_remap_rwx(page_gpa, hpa, allocator) {
            return None;
        }
        self.watchpoint_class.remove(page_gpa);
        self.state.exit_stats.wp_culled += 1;
        Some(ExitHandlerResult::Continue)
    }

    /// Arm a hardware data breakpoint on the EXACT address of a confirmed-shared
    /// write (DataCollider-style), so a later access to that byte/word by a
    /// *different* thread fires a `#DB` -- a realized data race. Unlike the EPT
    /// watchpoint this is byte-granular and costs no INVEPT (arming is register
    /// state programmed by the run loop). `#DB` interception is already enabled
    /// for the whole run by the feature flag (see `apply_intercept_db`). Returns
    /// whether a slot is now watching this address.
    ///
    /// The exact faulting linear address comes from `GuestLinearAddr`, set by the
    /// EPT violation; a page-granular address would defeat the whole point.
    fn wp_arm_dr(&mut self, owner_tid: u64) -> bool {
        let gva = self
            .state
            .vmcs
            .read_natural(VmcsFieldNatural::GuestLinearAddr)
            .unwrap_or(0);
        if gva == 0 {
            return false;
        }
        // RIP-window candidate filter. A candidate is only worth a scarce DR slot
        // if the racy access comes from code in the configured window (typically
        // the target executable's text): library-internal shared writes
        // (malloc/futex/stdio) fault from the shared-object mapping and would
        // otherwise monopolize all 4 slots, starving the cold in-target race
        // sites. Skip arming (but not the paired preemption, decided at the call
        // site) when the faulting RIP is out of window. Disabled when rip_hi == 0.
        let rip = self
            .state
            .vmcs
            .read_natural(VmcsFieldNatural::GuestRip)
            .unwrap_or(0);
        if !self.state.devices.apic.watchpoint_dr_rip_allowed(rip) {
            return false;
        }
        let len = self.state.devices.apic.watchpoint_dr_len();
        let epoch = self.wp_switch_epoch;
        match self.state.debug_watch.arm(gva, len, owner_tid, epoch) {
            ArmResult::Armed { .. } => self.state.exit_stats.wp_dr_armed += 1,
            ArmResult::Evicted { .. } => {
                self.state.exit_stats.wp_dr_armed += 1;
                self.state.exit_stats.wp_dr_evictions += 1;
            }
            ArmResult::AlreadyWatched { .. } => return true,
        }
        true
    }

    /// Get the parent's memory size.
    fn parent_memory_size(&self) -> usize {
        // SAFETY: Parent is valid as long as this ForkedVm exists (enforced by children_count)
        unsafe { (*self.parent).memory_size() }
    }

    /// Read a page from the parent.
    fn parent_read_page(&self, gpa: GuestPhysAddr) -> Option<*const u8> {
        // SAFETY: Parent is valid as long as this ForkedVm exists (enforced by children_count)
        unsafe { (*self.parent).read_page(gpa) }
    }
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> VmContext
    for ForkedVm<V, P, I>
{
    type Vmcs = V;
    type V = <V::M as Machine>::V;
    type I = I;
    type CowPage = P;

    fn state(&self) -> &VmState<Self::Vmcs, Self::I> {
        &self.state
    }

    fn state_mut(&mut self) -> &mut VmState<Self::Vmcs, Self::I> {
        &mut self.state
    }

    fn read_guest_memory(&self, gpa: GuestPhysAddr, buf: &mut [u8]) -> Result<(), MemoryError> {
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);
        let page_offset = (gpa.as_u64() & 0xFFF) as usize;

        // Check if we have a COW page for this GPA
        if let Some(cow_page) = <CowPageMap<P>>::get(&self.cow_pages, page_gpa) {
            // Read from COW page
            let cow_ptr = Page::virtual_address(cow_page).as_u64() as *const u8;
            let available_in_page = PAGE_SIZE - page_offset;

            if buf.len() <= available_in_page {
                // Read fits in single page
                // SAFETY: cow_ptr points to a valid COW page; page_offset + buf.len() <= PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        cow_ptr.add(page_offset),
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                }
            } else {
                // Read spans pages - read what we can from this page
                // SAFETY: cow_ptr points to a valid COW page; page_offset + available_in_page == PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        cow_ptr.add(page_offset),
                        buf.as_mut_ptr(),
                        available_in_page,
                    );
                }
                // Recursively read the rest from next page(s)
                self.read_guest_memory(
                    GuestPhysAddr::new(page_gpa.as_u64() + PAGE_SIZE as u64),
                    &mut buf[available_in_page..],
                )?;
            }
        } else {
            // Read from parent (walks COW chain for nested forks)
            let parent_page = self
                .parent_read_page(page_gpa)
                .ok_or(MemoryError::OutOfRange)?;
            let available_in_page = PAGE_SIZE - page_offset;

            if buf.len() <= available_in_page {
                // SAFETY: parent_page points to a valid parent memory page; page_offset + buf.len() <= PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        parent_page.add(page_offset),
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                }
            } else {
                // Read spans pages
                // SAFETY: parent_page points to a valid parent memory page; page_offset + available_in_page == PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        parent_page.add(page_offset),
                        buf.as_mut_ptr(),
                        available_in_page,
                    );
                }
                self.read_guest_memory(
                    GuestPhysAddr::new(page_gpa.as_u64() + PAGE_SIZE as u64),
                    &mut buf[available_in_page..],
                )?;
            }
        }
        Ok(())
    }

    fn write_guest_memory(&mut self, gpa: GuestPhysAddr, buf: &[u8]) -> Result<(), MemoryError> {
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);
        let page_offset = (gpa.as_u64() & 0xFFF) as usize;

        // Check if we have a COW page for this GPA
        if let Some(cow_page) = self.cow_pages.get_mut(page_gpa) {
            // Write to COW page
            let cow_ptr = cow_page.virtual_address().as_u64() as *mut u8;
            let available_in_page = PAGE_SIZE - page_offset;

            if buf.len() <= available_in_page {
                // SAFETY: cow_ptr points to a valid writable COW page; page_offset + buf.len() <= PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buf.as_ptr(),
                        cow_ptr.add(page_offset),
                        buf.len(),
                    );
                }
            } else {
                // Write spans pages
                // SAFETY: cow_ptr points to a valid writable COW page; page_offset + available_in_page == PAGE_SIZE.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buf.as_ptr(),
                        cow_ptr.add(page_offset),
                        available_in_page,
                    );
                }
                self.write_guest_memory(
                    GuestPhysAddr::new(page_gpa.as_u64() + PAGE_SIZE as u64),
                    &buf[available_in_page..],
                )?;
            }
            Ok(())
        } else {
            // Page not COW'd yet - this shouldn't normally happen as writes
            // should go through EPT fault -> handle_cow_fault first.
            // Return an error to indicate the page needs COW handling.
            Err(MemoryError::PermissionDenied)
        }
    }

    fn handle_cow_fault<A: CowAllocator<Self::CowPage>>(
        &mut self,
        gpa: GuestPhysAddr,
        allocator: &mut A,
    ) -> Option<ExitHandlerResult> {
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);

        // Check if we already have a COW page for this address
        if self.cow_pages.contains(page_gpa) {
            // EPT write-watchpoint hit: an already-COW'd page that was
            // deliberately left R+E (armed) is faulting on a write. It is told
            // apart from an ordinary (RWX) COW'd page by its EPT permissions.
            if self.state.devices.apic.watchpoint_pct != 0 {
                if let Some((hpa, perms)) = self.state.ept.lookup(allocator, page_gpa) {
                    if perms == EptPermissions::READ_EXECUTE {
                        // Diagnostic counters (observability only), surfaced via
                        // exit_stats -> GET_EXIT_STATS -> bedrock-cli stdout.
                        self.state.exit_stats.wp_faults += 1;
                        // Armed watchpoint hit. Thread id = guest FS_BASE (the
                        // per-thread TLS base); CPL from the CS selector's low 2
                        // bits. Both are deterministic VMCS reads at a
                        // deterministic EPT fault.
                        let cpl = self
                            .state
                            .vmcs
                            .read16(VmcsField16::GuestCsSelector)
                            .unwrap_or(0)
                            & 3;
                        let tid = self
                            .state
                            .vmcs
                            .read_natural(VmcsFieldNatural::GuestFsBase)
                            .unwrap_or(0);

                        // Track userspace thread switches to drive the cull
                        // epoch: a new tid at CPL 3 means the guest scheduler
                        // switched threads since the last watchpoint fault.
                        if cpl == 3 && tid != self.wp_last_tid {
                            self.wp_last_tid = tid;
                            self.wp_switch_epoch = self.wp_switch_epoch.wrapping_add(1);
                            self.state.exit_stats.wp_epoch = u64::from(self.wp_switch_epoch);
                        }

                        // Snapshot the classification (ends the map borrow). A
                        // missing record for an armed page is not expected; fail
                        // safe by treating it as confirmed (keep watching).
                        let rec = self.watchpoint_class.get_mut(page_gpa).map(|c| *c);
                        let confirmed = rec.map(|r| r.confirmed).unwrap_or(true);

                        // A confirmed-shared page behaves like B1: preempt at
                        // this access with probability watchpoint_pct, else let
                        // the write through and single-step it. The no-grant-W
                        // preempt path is taken only when the vector could
                        // actually be raised (else fall through so the guest
                        // always makes progress); watchpoint_should_preempt still
                        // advances its PRNG on every CPL 3 confirmed hit.
                        if confirmed {
                            // Hardware data-breakpoint mode (DataCollider): on a
                            // sampled write (probability watchpoint_pct), arm a DR
                            // on the exact faulting address for this thread AND
                            // force a preemption, so another thread runs into the
                            // breakpoint. A #DB from a different thread is then a
                            // realized race. Arming is GATED on the same coin flip
                            // as the preemption: otherwise every write to a
                            // confirmed page arms a slot, and with only 4 slots the
                            // set thrashes (a fresh slot is evicted before the
                            // other thread reaches it). The write is let through
                            // (the DR, not the EPT page, watches the location), so
                            // this pays no per-write INVEPT.
                            if self.state.devices.apic.watchpoint_dr {
                                if cpl == 3 && self.state.devices.apic.watchpoint_should_preempt() {
                                    self.wp_arm_dr(tid);
                                    if raise_preempt_vector(&mut self.state.devices.apic) {
                                        self.state.exit_stats.wp_preempts += 1;
                                    }
                                }
                                return self.wp_grant_and_leave(page_gpa, hpa, allocator);
                            }
                            if cpl == 3
                                && self.state.devices.apic.watchpoint_should_preempt()
                                && raise_preempt_vector(&mut self.state.devices.apic)
                            {
                                self.state.exit_stats.wp_preempts += 1;
                                return Some(ExitHandlerResult::Continue);
                            }
                            return self.wp_grant_and_leave(page_gpa, hpa, allocator);
                        }

                        // Classifying: record present and not yet confirmed.
                        let rec = match rec {
                            Some(r) => r,
                            // Unreachable given the `confirmed` handling above,
                            // but avoid a panic: just let the write through.
                            None => return self.wp_grant_and_leave(page_gpa, hpa, allocator),
                        };
                        if cpl != 3 {
                            // Do not classify on kernel faults: FS_BASE at CPL 0
                            // is not the userspace thread id. Just let it through.
                            return self.wp_grant_and_leave(page_gpa, hpa, allocator);
                        }
                        if tid != rec.first_tid {
                            // A second distinct thread wrote this page: confirm it
                            // shared, then act shared for this very fault.
                            if let Some(c) = self.watchpoint_class.get_mut(page_gpa) {
                                c.confirmed = true;
                            }
                            self.state.exit_stats.wp_confirmed += 1;
                            // DR mode: arm on the exact address at the moment we
                            // confirm the page shared (this fault is already a
                            // second-thread write, the strongest candidate).
                            if self.state.devices.apic.watchpoint_dr {
                                self.wp_arm_dr(tid);
                                if self.state.devices.apic.watchpoint_should_preempt()
                                    && raise_preempt_vector(&mut self.state.devices.apic)
                                {
                                    self.state.exit_stats.wp_preempts += 1;
                                }
                                return self.wp_grant_and_leave(page_gpa, hpa, allocator);
                            }
                            if self.state.devices.apic.watchpoint_should_preempt()
                                && raise_preempt_vector(&mut self.state.devices.apic)
                            {
                                self.state.exit_stats.wp_preempts += 1;
                                return Some(ExitHandlerResult::Continue);
                            }
                            return self.wp_grant_and_leave(page_gpa, hpa, allocator);
                        }
                        // Same thread as the first writer. Count the fault, and
                        // cull the page (grant W permanently) once it has survived
                        // WP_CULL_EPOCHS observed thread switches or hit the fault
                        // cap: it is thread-local, not shared.
                        let new_count = rec.fault_count.saturating_add(1);
                        if let Some(c) = self.watchpoint_class.get_mut(page_gpa) {
                            c.fault_count = new_count;
                        }
                        let cull_epochs = self.state.devices.apic.watchpoint_cull_epochs;
                        let cull_cap = self.state.devices.apic.watchpoint_cull_cap;
                        if self.wp_switch_epoch.wrapping_sub(rec.arm_epoch) >= cull_epochs
                            || new_count >= cull_cap
                        {
                            return self.wp_cull(page_gpa, hpa, allocator);
                        }
                        return self.wp_grant_and_leave(page_gpa, hpa, allocator);
                    }
                }
            }
            // Already copied - this means the EPT was already remapped to RWX but
            // the TLB still had a stale R+X entry. The EPT violation auto-invalidates
            // the stale entry, so the retry will use the correct mapping.
            self.state.exit_stats.cow.stale_tlb_faults += 1;
            if self.state.exit_stats.cow.stale_tlb_faults == 1 {
                log_err!(
                    "COW: stale TLB EPT violation for already-COW'd page GPA={:#x}\n",
                    page_gpa.as_u64()
                );
            }
            return Some(ExitHandlerResult::Continue);
        }

        // Allocate a new page for COW
        let new_page = match allocator.allocate_cow_page() {
            Ok(page) => page,
            Err(_) => {
                log_err!(
                    "COW: Failed to allocate page for GPA {:#x}\n",
                    page_gpa.as_u64()
                );
                return None;
            }
        };

        // Get virtual address for copying
        let new_page_virt = new_page.virtual_address().as_u64() as *mut u8;
        let new_page_phys = new_page.physical_address();

        // Copy content from parent (walks COW chain for nested forks)
        let parent_page = match self.parent_read_page(page_gpa) {
            Some(ptr) => ptr,
            None => {
                log_err!(
                    "COW: GPA {:#x} out of parent memory range\n",
                    page_gpa.as_u64()
                );
                return None;
            }
        };

        // SAFETY: parent_page points to a valid PAGE_SIZE parent page; new_page_virt
        // points to a freshly-allocated PAGE_SIZE page. The regions do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(parent_page, new_page_virt, PAGE_SIZE);
        }

        // Insert into COW page map
        if self.cow_pages.insert(page_gpa, new_page).is_err() {
            log_err!("COW: Failed to insert page into COW map\n");
            return None;
        }

        // Remap EPT entry to point to the new page. Normally RWX; but if EPT
        // write-watchpoints are enabled and this first write came from userspace
        // (CPL 3), leave the page R+E so every later write to it faults back out
        // (an armed watchpoint). The faulting instruction then retries,
        // re-faults, and lands in the cow_pages branch above. Kernel-written
        // pages (CPL 0) get plain RWX and are never watched, which keeps boot
        // and kernel writes fast.
        let arm_watchpoint = self.state.devices.apic.watchpoint_pct != 0
            && (self
                .state
                .vmcs
                .read16(VmcsField16::GuestCsSelector)
                .unwrap_or(0)
                & 3)
                == 3;
        let new_perms = if arm_watchpoint {
            EptPermissions::READ_EXECUTE
        } else {
            EptPermissions::READ_WRITE_EXECUTE
        };
        if let Err(_e) = self.state.ept.remap_4k(
            allocator,
            page_gpa,
            new_page_phys,
            new_perms,
            EptMemoryType::WriteBack,
        ) {
            log_err!(
                "COW: Failed to remap EPT for GPA {:#x}\n",
                page_gpa.as_u64()
            );
            return None;
        }

        // SDM Vol 3C §30.4.3.4 requires single-context INVEPT after changing
        // the HPA in an EPT leaf. The EPT-violation auto-invalidation only
        // covers the faulting linear address; combined mappings cached for
        // other GVAs that target this GPA (e.g. the kernel just faulted via
        // its tmpfs mapping, but a user-space mmap of the same file has its
        // own combined mapping in the TLB) would otherwise keep the old
        // HPA and read pre-COW data.
        let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());

        // If this page armed as a watchpoint, record its classification: the
        // first writer thread (guest FS_BASE) and the current switch epoch, so
        // the arm-then-cull logic in the cow_pages branch can later cull it
        // (single-writer) or confirm it shared (multiple distinct writers).
        if arm_watchpoint {
            let tid = self
                .state
                .vmcs
                .read_natural(VmcsFieldNatural::GuestFsBase)
                .unwrap_or(0);
            if self
                .watchpoint_class
                .insert(
                    page_gpa,
                    WpClass {
                        first_tid: tid,
                        arm_epoch: self.wp_switch_epoch,
                        fault_count: 0,
                        confirmed: false,
                    },
                )
                .is_err()
            {
                log_err!(
                    "watchpoint: failed to record classification for GPA {:#x}\n",
                    page_gpa.as_u64()
                );
            }
            self.state.exit_stats.wp_armed += 1;
        }

        log_debug!(
            "COW: Copied page at GPA {:#x} -> HPA {:#x}\n",
            page_gpa.as_u64(),
            new_page_phys.as_u64()
        );

        // Return Continue to retry the faulting instruction
        Some(ExitHandlerResult::Continue)
    }

    fn is_forked(&self) -> bool {
        true
    }

    fn rearm_watchpoints<A: CowAllocator<Self::CowPage>>(&mut self, allocator: &mut A) {
        if self.state.devices.apic.watchpoint_pct == 0 {
            return;
        }
        // Re-protect every tracked watchpoint page that is currently writable
        // (was let through since the last re-arm) back to R+E, so its next write
        // faults and can preempt again. Pages already R+E (never granted this
        // window, or holding after a preempt refault) are skipped. Disjoint
        // field borrows: iterate the classification map while remapping through
        // `state.ept` -- `&mut self` method calls would alias, so split first.
        let Self {
            watchpoint_class,
            state,
            ..
        } = self;
        let mut rearmed = 0u64;
        // Iterate by page GPA. remap_4k only touches the leaf for that GPA, so
        // mutating the EPT while iterating the (separate) class map is sound; no
        // GPA list is collected first, keeping this off the 8KB kernel stack.
        for page_gpa in watchpoint_class.iter() {
            if let Some((hpa, perms)) = state.ept.lookup(allocator, page_gpa) {
                if perms == EptPermissions::READ_WRITE_EXECUTE {
                    let _ = state.ept.remap_4k(
                        allocator,
                        page_gpa,
                        hpa,
                        EptPermissions::READ_EXECUTE,
                        EptMemoryType::WriteBack,
                    );
                    rearmed += 1;
                }
            }
        }
        // One INVEPT for the whole batch (not one per page): the point of
        // sampling is to pay a single flush per window instead of per write.
        if rearmed > 0 {
            let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(state.ept.eptp());
            state.exit_stats.wp_rearms += 1;
            state.exit_stats.wp_rearm_pages += rearmed;
        }
    }

    fn cow_feedback_buffer_for_mapping<A: CowAllocator<Self::CowPage>>(
        &mut self,
        index: usize,
        allocator: &mut A,
    ) {
        let feedback_buffer = match self.state.feedback_buffers.get(index) {
            Some(fb) => **fb,
            None => return,
        };

        for i in 0..feedback_buffer.num_pages {
            let page_gpa = GuestPhysAddr::new(feedback_buffer.gpas[i]);

            // Skip pages already COW'd in this VM: re-copying would clobber a
            // guest write that happened before the mapping.
            if self.cow_pages.contains(page_gpa) {
                continue;
            }

            // Allocate a child-owned page for COW.
            let new_page = match allocator.allocate_cow_page() {
                Ok(page) => page,
                Err(_) => {
                    log_err!(
                        "cow_feedback_buffer_for_mapping: failed to allocate page for GPA {:#x}\n",
                        page_gpa.as_u64()
                    );
                    continue;
                }
            };

            let new_page_virt = new_page.virtual_address().as_u64() as *mut u8;
            let new_page_phys = new_page.physical_address();

            // Copy current contents from the parent chain.
            let parent_page = match self.parent_read_page(page_gpa) {
                Some(ptr) => ptr,
                None => {
                    log_err!(
                        "cow_feedback_buffer_for_mapping: GPA {:#x} out of parent memory range\n",
                        page_gpa.as_u64()
                    );
                    continue;
                }
            };

            // SAFETY: parent_page points to a valid PAGE_SIZE parent page; new_page_virt
            // points to a freshly-allocated PAGE_SIZE page. The regions do not overlap.
            unsafe {
                core::ptr::copy_nonoverlapping(parent_page, new_page_virt, PAGE_SIZE);
            }

            if self.cow_pages.insert(page_gpa, new_page).is_err() {
                log_err!("cow_feedback_buffer_for_mapping: failed to insert page into COW map\n");
                continue;
            }

            // Remap the EPT entry to the new page with RWX permissions, so the
            // guest writes directly to this (now mapped) frame with no further
            // fault or re-COW.
            if let Err(_e) = self.state.ept.remap_4k(
                allocator,
                page_gpa,
                new_page_phys,
                EptPermissions::READ_WRITE_EXECUTE,
                EptMemoryType::WriteBack,
            ) {
                log_err!(
                    "cow_feedback_buffer_for_mapping: failed to remap EPT for GPA {:#x}\n",
                    page_gpa.as_u64()
                );
                continue;
            }

            // SDM Vol 3C §30.4.3.4: single-context INVEPT after changing a
            // leaf's HPA. See the matching comment in handle_cow_fault.
            let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());

            log_debug!(
                "cow_feedback_buffer_for_mapping: COW'd buffer {} page at GPA {:#x} -> HPA {:#x}\n",
                index,
                page_gpa.as_u64(),
                new_page_phys.as_u64()
            );
        }
    }

    fn pre_cow_io_channel_page<A: CowAllocator<Self::CowPage>>(&mut self, allocator: &mut A) {
        let page_gpa_raw = self.state.io_channel.page_gpa;
        if page_gpa_raw == 0 {
            return;
        }
        let page_gpa = GuestPhysAddr::new(page_gpa_raw & !0xFFF);

        // Already CoW'd — nothing to do.
        if self.cow_pages.contains(page_gpa) {
            return;
        }

        let new_page = match allocator.allocate_cow_page() {
            Ok(page) => page,
            Err(_) => {
                log_err!(
                    "pre_cow_io_channel_page: failed to allocate page for GPA {:#x}\n",
                    page_gpa.as_u64()
                );
                return;
            }
        };
        let new_page_virt = new_page.virtual_address().as_u64() as *mut u8;
        let new_page_phys = new_page.physical_address();

        // Copy current contents from parent so the guest module's view
        // of the page is preserved (the kernel module may have initial
        // bookkeeping on it).
        let parent_page = match self.parent_read_page(page_gpa) {
            Some(ptr) => ptr,
            None => {
                log_err!(
                    "pre_cow_io_channel_page: GPA {:#x} out of parent memory range\n",
                    page_gpa.as_u64()
                );
                return;
            }
        };
        // SAFETY: parent_page points to a valid PAGE_SIZE parent page;
        // new_page_virt points to a freshly-allocated PAGE_SIZE page. The
        // regions do not overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(parent_page, new_page_virt, PAGE_SIZE);
        }

        if self.cow_pages.insert(page_gpa, new_page).is_err() {
            log_err!("pre_cow_io_channel_page: failed to insert page into COW map\n");
            return;
        }

        if let Err(_e) = self.state.ept.remap_4k(
            allocator,
            page_gpa,
            new_page_phys,
            EptPermissions::READ_WRITE_EXECUTE,
            EptMemoryType::WriteBack,
        ) {
            log_err!(
                "pre_cow_io_channel_page: failed to remap EPT for GPA {:#x}\n",
                page_gpa.as_u64()
            );
            return;
        }

        // SDM Vol 3C §30.4.3.4: single-context INVEPT after changing a leaf's
        // HPA. See the matching comment in handle_cow_fault.
        let _ = <<V::M as Machine>::V as Vmx>::invept_single_context(self.state.ept.eptp());

        log_debug!(
            "pre_cow_io_channel_page: pre-COW'd I/O channel page at GPA {:#x} -> HPA {:#x}\n",
            page_gpa.as_u64(),
            new_page_phys.as_u64()
        );
    }

    fn finalize_exit_record<K: Kernel>(&mut self, _kernel: &K) {
        // Nothing to do unless an `Exit` event awaits its deferred memory hash.
        if self.state.pending_exit_loc.is_none() {
            return;
        }

        let memory_hash = if self.state.skip_memory_hash {
            0
        } else {
            match self.state.exit_trigger {
                ExitTrigger::AtTsc
                | ExitTrigger::AtShutdown
                | ExitTrigger::AllExits
                | ExitTrigger::Checkpoints
                | ExitTrigger::TscRange => {
                    // Hash only COW (modified) pages for forked VMs.
                    // This captures the delta from parent, which is what matters
                    // for comparing forked VM states.
                    let mut hasher = Xxh64Hasher::new();

                    for (gpa, cow_page) in self.cow_pages.iter() {
                        // Include GPA in hash so page position matters
                        hasher.write_u64(gpa.as_u64());
                        let page_ptr = Page::virtual_address(cow_page).as_u64() as *const u8;
                        // SAFETY: page_ptr points to a valid COW page of PAGE_SIZE bytes.
                        let page = unsafe { core::slice::from_raw_parts(page_ptr, PAGE_SIZE) };
                        hasher.write_bytes(page);
                    }

                    hasher.finish()
                }
                ExitTrigger::Disabled => 0,
            }
        };

        // Patch the pending `Exit` record's memory_hash and cow_page_count in
        // the event buffer.
        let cow_page_count = self.cow_pages.len() as u32;
        self.state
            .finalize_exit_memory_hash(memory_hash, cow_page_count);
    }
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> ParentVm
    for ForkedVm<V, P, I>
{
    fn read_page(&self, gpa: GuestPhysAddr) -> Option<*const u8> {
        // Align to page boundary
        let page_gpa = GuestPhysAddr::new(gpa.as_u64() & !0xFFF);

        // First check our COW pages
        if let Some(page) = <CowPageMap<P>>::get(&self.cow_pages, page_gpa) {
            Some(Page::virtual_address(page).as_u64() as *const u8)
        } else {
            // Delegate to parent (walks COW chain for nested forks)
            self.parent_read_page(page_gpa)
        }
    }

    fn memory_size(&self) -> usize {
        self.parent_memory_size()
    }

    fn remove_child(&self) {
        self.children_count.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> ForkableVm<V, I>
    for ForkedVm<V, P, I>
{
    type Page = P;

    fn vm_state(&self) -> &VmState<V, I> {
        &self.state
    }

    fn vm_state_mut(&mut self) -> &mut VmState<V, I> {
        &mut self.state
    }

    fn add_child(&self) {
        self.children_count.fetch_add(1, Ordering::SeqCst);
    }

    fn remove_child(&self) {
        self.children_count.fetch_sub(1, Ordering::SeqCst);
    }

    fn children_count(&self) -> usize {
        self.children_count.load(Ordering::SeqCst)
    }
}

/// Ensure VMCS is cleared and parent notified when ForkedVm is dropped.
impl<V: VirtualMachineControlStructure, P: Page, I: InstructionCounter> Drop for ForkedVm<V, P, I> {
    fn drop(&mut self) {
        // Clear the VMCS to transition it to "clear" state
        if let Err(_e) = self.state.vmcs.clear() {
            log_err!("Failed to clear VMCS during ForkedVm drop\n");
        }
        // Return the VPID to the pool for reuse
        deallocate_vpid(self.state.vpid);
        // Decrement parent's children count
        // SAFETY: Parent is valid as long as children_count > 0, which it is since
        // we're still alive (about to drop). The parent pointer is valid.
        unsafe {
            (*self.parent).remove_child();
        }
    }
}
