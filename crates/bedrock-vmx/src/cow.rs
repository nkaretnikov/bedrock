// SPDX-License-Identifier: GPL-2.0

//! Copy-on-write page tracking for forked VMs.
//!
//! This module provides the `CowPageMap` structure for tracking pages that have
//! been copied during copy-on-write handling in forked VMs.
//!
//! In cargo builds, uses `alloc::collections::BTreeMap`.
//! In kernel builds, uses `kernel::rbtree::RBTree`.

/// Error returned when inserting a COW page fails (e.g., allocation failure).
#[derive(Debug, Clone, Copy)]
pub struct CowInsertError;

/// Per-page watchpoint classification record for the arm-then-cull directed
/// preemption strategy. Each armed userspace page starts as a watchpoint; this
/// record tracks the first writer thread (guest FS_BASE), the thread-switch
/// epoch at arm time, a fault counter, and whether the page has been confirmed
/// shared (written by >= 2 distinct threads). Single-writer pages are culled;
/// confirmed pages stay armed and drive preemption.
#[derive(Clone, Copy)]
pub struct WpClass {
    /// Guest FS_BASE of the thread that first wrote this page after it armed.
    pub first_tid: u64,
    /// `wp_switch_epoch` value when this page was armed.
    pub arm_epoch: u32,
    /// Number of write faults observed on this page while classifying.
    pub fault_count: u32,
    /// True once a second distinct thread has written this page.
    pub confirmed: bool,
}

// ============================================================================
// Cargo build: Use alloc::collections::BTreeMap
// ============================================================================

#[cfg(feature = "cargo")]
mod cargo_impl {
    extern crate alloc;

    use alloc::collections::BTreeMap;
    use memory::GuestPhysAddr;

    use crate::traits::Page;

    /// Tracks copy-on-write pages for a forked VM.
    ///
    /// Only stores pages that THIS VM has modified - ancestor pages are
    /// accessed via EPT lookup (the EPT already points to the correct
    /// host physical addresses from parent/grandparent/etc).
    pub struct CowPageMap<P: Page> {
        /// Maps page-aligned GPAs to owned pages.
        pages: BTreeMap<u64, P>,
        /// Number of pages in the map.
        count: usize,
    }

    impl<P: Page> CowPageMap<P> {
        /// Create a new empty COW page map.
        pub fn new() -> Self {
            Self {
                pages: BTreeMap::new(),
                count: 0,
            }
        }

        /// Get a reference to the COW page at the given GPA, if it exists.
        ///
        /// Returns None if the page has not been copied for this VM.
        pub fn get(&self, gpa: GuestPhysAddr) -> Option<&P> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.pages.get(&page_aligned)
        }

        /// Get a mutable reference to the COW page at the given GPA, if it exists.
        pub fn get_mut(&mut self, gpa: GuestPhysAddr) -> Option<&mut P> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.pages.get_mut(&page_aligned)
        }

        /// Insert a new COW page for the given GPA.
        ///
        /// The GPA will be page-aligned before insertion.
        pub fn insert(&mut self, gpa: GuestPhysAddr, page: P) -> Result<(), super::CowInsertError> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            if self.pages.insert(page_aligned, page).is_none() {
                self.count += 1;
            }
            Ok(())
        }

        /// Check if a COW page exists for the given GPA.
        pub fn contains(&self, gpa: GuestPhysAddr) -> bool {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.pages.contains_key(&page_aligned)
        }

        /// Get the number of COW pages.
        pub fn len(&self) -> usize {
            self.count
        }

        /// Check if the map is empty.
        pub fn is_empty(&self) -> bool {
            self.count == 0
        }

        /// Iterate over all COW pages.
        ///
        /// Yields (GPA, Page) pairs where GPA is page-aligned.
        pub fn iter(&self) -> impl Iterator<Item = (GuestPhysAddr, &P)> {
            self.pages
                .iter()
                .map(|(&gpa, page)| (GuestPhysAddr::new(gpa), page))
        }
    }

    impl<P: Page> Default for CowPageMap<P> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Maps page-aligned GPAs to per-page watchpoint classification records
    /// (arm-then-cull). Mirrors `CowPageMap` but holds `WpClass` values.
    pub struct WatchpointClassMap {
        classes: BTreeMap<u64, super::WpClass>,
    }

    impl WatchpointClassMap {
        /// Create a new empty classification map.
        pub fn new() -> Self {
            Self {
                classes: BTreeMap::new(),
            }
        }

        /// Record (or replace) the classification for a page.
        pub fn insert(
            &mut self,
            gpa: GuestPhysAddr,
            class: super::WpClass,
        ) -> Result<(), super::CowInsertError> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.classes.insert(page_aligned, class);
            Ok(())
        }

        /// Get a mutable reference to a page's classification, if present.
        pub fn get_mut(&mut self, gpa: GuestPhysAddr) -> Option<&mut super::WpClass> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.classes.get_mut(&page_aligned)
        }
    }

    impl Default for WatchpointClassMap {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(feature = "cargo")]
pub use cargo_impl::{CowPageMap, WatchpointClassMap};

// ============================================================================
// Kernel build: Use kernel::rbtree::RBTree
// ============================================================================

#[cfg(not(feature = "cargo"))]
mod kernel_impl {
    use kernel::alloc::flags::GFP_ATOMIC;
    use kernel::rbtree::RBTree;

    use crate::memory::GuestPhysAddr;
    use crate::vmx::traits::Page;

    /// Tracks copy-on-write pages for a forked VM.
    ///
    /// Only stores pages that THIS VM has modified - ancestor pages are
    /// accessed via EPT lookup (the EPT already points to the correct
    /// host physical addresses from parent/grandparent/etc).
    pub struct CowPageMap<P: Page> {
        /// Maps page-aligned GPAs to owned pages.
        pages: RBTree<u64, P>,
        /// Number of pages in the map.
        count: usize,
    }

    impl<P: Page> CowPageMap<P> {
        /// Create a new empty COW page map.
        pub fn new() -> Self {
            Self {
                pages: RBTree::new(),
                count: 0,
            }
        }

        /// Get a reference to the COW page at the given GPA, if it exists.
        ///
        /// Returns None if the page has not been copied for this VM.
        pub fn get(&self, gpa: GuestPhysAddr) -> Option<&P> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.pages.get(&page_aligned)
        }

        /// Get a mutable reference to the COW page at the given GPA, if it exists.
        pub fn get_mut(&mut self, gpa: GuestPhysAddr) -> Option<&mut P> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.pages.get_mut(&page_aligned)
        }

        /// Insert a new COW page for the given GPA.
        ///
        /// The GPA will be page-aligned before insertion.
        /// Returns `Err` if allocation fails.
        pub fn insert(&mut self, gpa: GuestPhysAddr, page: P) -> Result<(), super::CowInsertError> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            // try_create_and_insert allocates a node and inserts it
            match self
                .pages
                .try_create_and_insert(page_aligned, page, GFP_ATOMIC)
            {
                Ok(_) => {
                    self.count += 1;
                    Ok(())
                }
                Err(_) => Err(super::CowInsertError),
            }
        }

        /// Check if a COW page exists for the given GPA.
        pub fn contains(&self, gpa: GuestPhysAddr) -> bool {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.pages.get(&page_aligned).is_some()
        }

        /// Get the number of COW pages.
        pub fn len(&self) -> usize {
            self.count
        }

        /// Check if the map is empty.
        pub fn is_empty(&self) -> bool {
            self.count == 0
        }

        /// Iterate over all COW pages.
        ///
        /// Yields (GPA, Page) pairs where GPA is page-aligned.
        pub fn iter(&self) -> impl Iterator<Item = (GuestPhysAddr, &P)> {
            self.pages
                .iter()
                .map(|(gpa, page)| (GuestPhysAddr::new(*gpa), page))
        }
    }

    impl<P: Page> Default for CowPageMap<P> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Maps page-aligned GPAs to per-page watchpoint classification records
    /// (arm-then-cull). Mirrors `CowPageMap` but holds `WpClass` values.
    pub struct WatchpointClassMap {
        classes: RBTree<u64, super::WpClass>,
    }

    impl WatchpointClassMap {
        /// Create a new empty classification map.
        pub fn new() -> Self {
            Self {
                classes: RBTree::new(),
            }
        }

        /// Record (or replace) the classification for a page.
        pub fn insert(
            &mut self,
            gpa: GuestPhysAddr,
            class: super::WpClass,
        ) -> Result<(), super::CowInsertError> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            match self
                .classes
                .try_create_and_insert(page_aligned, class, GFP_ATOMIC)
            {
                Ok(_) => Ok(()),
                Err(_) => Err(super::CowInsertError),
            }
        }

        /// Get a mutable reference to a page's classification, if present.
        pub fn get_mut(&mut self, gpa: GuestPhysAddr) -> Option<&mut super::WpClass> {
            let page_aligned = gpa.as_u64() & !0xFFF;
            self.classes.get_mut(&page_aligned)
        }
    }

    impl Default for WatchpointClassMap {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(not(feature = "cargo"))]
pub use kernel_impl::{CowPageMap, WatchpointClassMap};
