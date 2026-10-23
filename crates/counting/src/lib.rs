//! Allocators for tests that count what has been allocated and not yet freed, so a test can hold
//! a store's charge to what its structures really allocate: [`Counting`] counts each thread's
//! own (tests run on many threads at once), [`CountingAll`] the whole process's (a test binary
//! with one test, measuring what a structure allocates whichever thread allocates it). A crate's
//! test binary installs one (`#[global_allocator]`).
//!
//! Test support only: Bazel marks it `testonly` and Cargo takes it as a dev-dependency, so no
//! production build reaches it. It is the one `unsafe` code a test of the crates that hold a key
//! needs (implementing `GlobalAlloc` is unsafe by definition), kept out of those crates, which
//! deny `unsafe` outside their libc modules (`tally_wire`'s `kernel_clock`, the relay's `os`, the
//! feeder's `privilege`, the load harness's `os`). Before, it lived in `tally_wire::footprint`,
//! so the wire crate, which holds every key, allowed `unsafe` everywhere.

/// An allocator that counts what each thread has allocated and not yet freed, for a test to hold
/// a store's charge to what its structures really allocate ([`Counting::live`]): the system's,
/// with a counter a thread keeps of its own, so tests running on other threads at once do not
/// disturb it. A crate's test binary installs it (`#[global_allocator]`); a structure measured
/// must be built, changed and dropped on the thread that reads it.
pub struct Counting;

thread_local! {
    static LIVE: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
    static PEAK: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
}

impl Counting {
    /// What this thread has allocated and not yet freed, since it started.
    pub fn live() -> isize {
        LIVE.try_with(std::cell::Cell::get).unwrap_or(0)
    }

    /// What this thread allocated since `base` (a reading of [`Counting::live`]).
    pub fn since(base: isize) -> isize {
        Self::live() - base
    }

    /// A reading of [`Counting::live`] from which [`Counting::peak_since`] measures: the most
    /// this thread holds is counted afresh from here.
    pub fn peak_base() -> isize {
        let live = Self::live();
        let _ = PEAK.try_with(|peak| peak.set(live));
        live
    }

    /// The most this thread held at once since `base` (a reading of [`Counting::peak_base`]),
    /// above `base`: what a step allocated at its height, freed or not.
    pub fn peak_since(base: isize) -> isize {
        PEAK.try_with(std::cell::Cell::get).unwrap_or(base) - base
    }

    fn count(bytes: isize) {
        let _ = LIVE.try_with(|live| {
            let now = live.get() + bytes;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }
}

// SAFETY: every call is the system allocator's, with the same arguments; the counter is the
// calling thread's own.
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        Self::count(layout.size() as isize);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        Self::count(layout.size() as isize);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        Self::count(-(layout.size() as isize));
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        Self::count(new_size as isize - layout.size() as isize);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
    }
}

/// An allocator that counts what the whole process has allocated and not yet freed, the most at
/// once ([`CountingAll::peak_since`]) and the allocations live ([`CountingAll::allocations`]):
/// for a test binary that runs one test, so nothing else allocates while it measures
/// (`tally_wire`'s `footprint_bytes`, the relay's `figures_bytes`, the solver's `held_bytes`).
/// The system's, with counters the process shares.
pub struct CountingAll;

static ALL_LIVE: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
static ALL_PEAK: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
static ALL_ALLOCATIONS: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

impl CountingAll {
    /// What the process has allocated and not yet freed, since it started.
    pub fn live() -> isize {
        ALL_LIVE.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// What the process allocated since `base` (a reading of [`CountingAll::live`]).
    pub fn since(base: isize) -> isize {
        Self::live() - base
    }

    /// A reading of [`CountingAll::live`] from which [`CountingAll::peak_since`] measures.
    pub fn peak_base() -> isize {
        let live = Self::live();
        ALL_PEAK.store(live, std::sync::atomic::Ordering::Relaxed);
        live
    }

    /// The most the process held at once since `base` (a reading of
    /// [`CountingAll::peak_base`]), above `base`.
    pub fn peak_since(base: isize) -> isize {
        ALL_PEAK.load(std::sync::atomic::Ordering::Relaxed) - base
    }

    /// How many allocations the process holds and has not yet freed, since it started.
    pub fn allocations() -> isize {
        ALL_ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn count(bytes: isize) {
        let now = ALL_LIVE.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed) + bytes;
        ALL_PEAK.fetch_max(now, std::sync::atomic::Ordering::Relaxed);
    }

    fn allocated(allocations: isize) {
        ALL_ALLOCATIONS.fetch_add(allocations, std::sync::atomic::Ordering::Relaxed);
    }
}

// SAFETY: every call is the system allocator's, with the same arguments; the counters are atomic.
unsafe impl std::alloc::GlobalAlloc for CountingAll {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        Self::count(layout.size() as isize);
        Self::allocated(1);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        Self::count(layout.size() as isize);
        Self::allocated(1);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        Self::count(-(layout.size() as isize));
        Self::allocated(-1);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        Self::count(new_size as isize - layout.size() as isize);
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
    }
}
