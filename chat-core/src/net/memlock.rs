// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Keeping secrets out of swap where the limit on locked memory is finite: a region locked into
//! memory (and left out of core dumps), which the allocations of the code that handles secrets come
//! from. That's the threads and tasks marked with [`lock_this_thread`] and [`Locked`]: an
//! interface's own thread, and each room's task. Everything else (Tor's and the relays' tasks, big
//! buffers such as pictures) uses ordinary memory, and so does an allocation once the region is
//! full. A block is zeroed when it's freed.
//!
//! An interface makes [`LockedAlloc`] its global allocator; [`crate::harden_process`] sets the
//! region up.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Blocks come in powers of two from MIN to MAX bytes, cut from chunks of CHUNK.
const MIN: usize = 16;
const MAX: usize = 16 * 1024;
const CHUNK: usize = 64 * 1024;
const CLASSES: usize = (MAX.trailing_zeros() - MIN.trailing_zeros() + 1) as usize;
/// The most the region takes, and the least worth having.
#[cfg(unix)]
const REGION_MAX: usize = 64 << 20;
#[cfg(unix)]
const REGION_MIN: usize = 1 << 20;

thread_local! {
    /// This thread's allocations come from the locked region while it's above 0.
    static SCOPE: Cell<u32> = const { Cell::new(0) };
}

/// Where the region is, for a quick test of whether a pointer is in it.
static BASE: AtomicUsize = AtomicUsize::new(0);
static END: AtomicUsize = AtomicUsize::new(0);
static ARENA: Mutex<Arena> = Mutex::new(Arena::empty());

/// The locked region: chunks cut from its start, each class's blocks from its own chunk, and each
/// class's freed blocks, linked through their first word.
struct Arena {
    next: usize,
    end: usize,
    cur: [usize; CLASSES],
    cur_end: [usize; CLASSES],
    free: [usize; CLASSES],
}

impl Arena {
    const fn empty() -> Arena {
        Arena {
            next: 0,
            end: 0,
            cur: [0; CLASSES],
            cur_end: [0; CLASSES],
            free: [0; CLASSES],
        }
    }

    /// The class a layout's block is in, or None for one too big.
    fn class(l: &Layout) -> Option<usize> {
        let size = l.size().max(l.align()).max(MIN).next_power_of_two();
        (size <= MAX).then(|| (size.trailing_zeros() - MIN.trailing_zeros()) as usize)
    }

    /// A block of class c, or None once the region is used up.
    ///
    /// # Safety
    /// The region must be the caller's, as `init` gave it.
    unsafe fn take(&mut self, c: usize) -> Option<*mut u8> {
        let size = MIN << c;
        if self.free[c] != 0 {
            let p = self.free[c] as *mut usize;
            // SAFETY: a freed block of this class, which holds the next one's address.
            self.free[c] = unsafe { p.read() };
            unsafe { p.write(0) };
            return Some(p.cast());
        }
        if self.cur[c] + size > self.cur_end[c] {
            if self.next + CHUNK > self.end {
                return None;
            }
            self.cur[c] = self.next;
            self.cur_end[c] = self.next + CHUNK;
            self.next += CHUNK;
        }
        let p = self.cur[c];
        self.cur[c] += size;
        Some(p as *mut u8)
    }

    /// A block back, zeroed, on its class's list.
    ///
    /// # Safety
    /// `p` must be a block of class c that `take` gave.
    unsafe fn give(&mut self, p: *mut u8, c: usize) {
        // SAFETY: the whole block is ours, and big enough for a word.
        unsafe {
            std::ptr::write_bytes(p, 0, MIN << c);
            (p as *mut usize).write(self.free[c]);
        }
        self.free[c] = p as usize;
    }
}

fn in_region(p: *mut u8) -> bool {
    let p = p as usize;
    p >= BASE.load(Ordering::Acquire) && p < END.load(Ordering::Acquire)
}

fn arena() -> std::sync::MutexGuard<'static, Arena> {
    ARENA.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The global allocator that serves a marked thread from the locked region.
pub struct LockedAlloc;

unsafe impl GlobalAlloc for LockedAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if SCOPE.with(Cell::get) > 0
            && END.load(Ordering::Relaxed) != 0
            && let Some(c) = Arena::class(&l)
            // SAFETY: the region is set up (END isn't 0).
            && let Some(p) = unsafe { arena().take(c) }
        {
            return p;
        }
        // SAFETY: as GlobalAlloc's caller promises.
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if in_region(p) {
            let c = Arena::class(&l).expect("a block in the region has a class");
            // SAFETY: a block of this layout's class, from `take`.
            unsafe { arena().give(p, c) };
        } else {
            // SAFETY: as GlobalAlloc's caller promises.
            unsafe { System.dealloc(p, l) }
        }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        if !in_region(p) {
            // SAFETY: as GlobalAlloc's caller promises.
            return unsafe { System.realloc(p, l, new_size) };
        }
        // SAFETY: the caller promises new_size makes a valid layout with this alignment.
        let new = unsafe { Layout::from_size_align_unchecked(new_size, l.align()) };
        if Arena::class(&new) == Arena::class(&l) {
            return p;
        }
        // What was locked stays locked if it can: a new block from the region whatever the thread.
        let q = match Arena::class(&new) {
            Some(c) => unsafe { arena().take(c) }.unwrap_or_else(|| unsafe { System.alloc(new) }),
            None => unsafe { System.alloc(new) },
        };
        if !q.is_null() {
            // SAFETY: both blocks are at least as big as what's copied, and don't overlap.
            unsafe {
                std::ptr::copy_nonoverlapping(p, q, l.size().min(new_size));
                self.dealloc(p, l);
            }
        }
        q
    }
}

/// This thread's allocations come from the locked region from now on.
pub fn lock_this_thread() {
    SCOPE.with(|s| s.set(s.get() + 1));
}

/// A future whose allocations, each time it runs, come from the locked region: a room's task.
pub struct Locked<F>(pub F);

impl<F: std::future::Future> std::future::Future for Locked<F> {
    type Output = F::Output;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<F::Output> {
        /// Unmarks the thread when the poll ends, even by a panic.
        struct Unmark;
        impl Drop for Unmark {
            fn drop(&mut self) {
                SCOPE.with(|s| s.set(s.get() - 1));
            }
        }
        SCOPE.with(|s| s.set(s.get() + 1));
        let _unmark = Unmark;
        // SAFETY: the inner future is never moved out of its pin.
        unsafe { self.map_unchecked_mut(|l| &mut l.0) }.poll(cx)
    }
}

/// Sets the locked region up: as much as the limit on locked memory allows (its hard limit, which
/// any process may raise its own to), within REGION_MAX, less a margin for what else locks memory.
/// Nothing if even REGION_MIN can't be locked.
#[cfg(unix)]
pub(crate) fn init() {
    if END.load(Ordering::Acquire) != 0 {
        return;
    }
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit writes into the struct it's given; setrlimit only reads it.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) != 0 {
            return;
        }
        lim.rlim_cur = lim.rlim_max;
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim);
    }
    let limit = usize::try_from(lim.rlim_cur).unwrap_or(usize::MAX);
    let mut size = limit.saturating_sub(256 << 10).min(REGION_MAX) / CHUNK * CHUNK;
    while size >= REGION_MIN {
        // SAFETY: a new private mapping, extra for the alignment; only it is touched.
        unsafe {
            let raw = libc::mmap(
                std::ptr::null_mut(),
                size + CHUNK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if raw == libc::MAP_FAILED {
                return;
            }
            let base = (raw as usize).next_multiple_of(CHUNK);
            if libc::mlock(base as *const libc::c_void, size) == 0 {
                #[cfg(target_os = "linux")]
                libc::madvise(base as *mut libc::c_void, size, libc::MADV_DONTDUMP);
                let mut a = arena();
                a.next = base;
                a.end = base + size;
                drop(a);
                BASE.store(base, Ordering::Release);
                END.store(base + size, Ordering::Release);
                return;
            }
            libc::munmap(raw, size + CHUNK);
        }
        size = size / 2 / CHUNK * CHUNK;
    }
}

/// How much of the locked region is in use, and how big it is: (0, 0) without one.
pub fn usage() -> (usize, usize) {
    let a = arena();
    let base = BASE.load(Ordering::Acquire);
    (a.next.saturating_sub(base), a.end.saturating_sub(base))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_come_by_class_go_back_zeroed_and_run_out() {
        // A region of two chunks, aligned as init aligns one.
        let mut mem = vec![0u8; 3 * CHUNK];
        let base = (mem.as_mut_ptr() as usize).next_multiple_of(CHUNK);
        let mut a = Arena::empty();
        a.next = base;
        a.end = base + 2 * CHUNK;
        let l = Layout::from_size_align(40, 8).unwrap();
        let c = Arena::class(&l).unwrap();
        assert_eq!(MIN << c, 64);
        assert_eq!(Arena::class(&Layout::from_size_align(MAX + 1, 8).unwrap()), None);
        assert_eq!(Arena::class(&Layout::from_size_align(8, 32).unwrap()).map(|c| MIN << c), Some(32));
        unsafe {
            let p = a.take(c).unwrap();
            let q = a.take(c).unwrap();
            assert_eq!((p as usize % 64, q as usize - p as usize), (0, 64));
            std::ptr::write_bytes(p, 0xAA, 40);
            a.give(p, c);
            // Zeroed but for the link to the next free block (none).
            assert!(std::slice::from_raw_parts(p, 64).iter().all(|b| *b == 0));
            assert_eq!(a.take(c).unwrap(), p);
            // Another class takes the second chunk; a third class finds the region used up.
            let big = Arena::class(&Layout::from_size_align(MAX, 8).unwrap()).unwrap();
            assert!(a.take(big).is_some());
            let other = Arena::class(&Layout::from_size_align(200, 8).unwrap()).unwrap();
            assert!(a.take(other).is_none());
        }
    }
}
