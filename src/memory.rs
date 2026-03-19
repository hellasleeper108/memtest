use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap, munmap};
use std::ptr;

/// A large contiguous memory region allocated via mmap.
pub struct MemRegion {
    pub ptr: *mut u8,
    pub size: usize,
}

// SAFETY: We own the region exclusively and manage its lifetime carefully.
unsafe impl Send for MemRegion {}
unsafe impl Sync for MemRegion {}

impl MemRegion {
    /// Allocate `size` bytes via anonymous mmap, page-aligned.
    pub fn allocate(size: usize) -> Result<Self, String> {
        let aligned = (size + 4095) & !4095;
        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                aligned,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == MAP_FAILED {
            return Err(format!(
                "mmap({} MiB) failed: {}",
                aligned >> 20,
                std::io::Error::last_os_error()
            ));
        }
        Ok(MemRegion { ptr: ptr as *mut u8, size: aligned })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u64, self.size / 8) }
    }

    pub fn as_u64_slice_mut(&mut self) -> &mut [u64] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u64, self.size / 8) }
    }

    /// Flush all cache lines covering this region from the CPU caches,
    /// forcing subsequent reads to hit DRAM.
    #[cfg(target_arch = "x86_64")]
    pub fn flush_all(&self) {
        use std::arch::x86_64::{_mm_clflush, _mm_sfence};
        const CACHE_LINE: usize = 64;
        let mut addr = self.ptr;
        let end = unsafe { self.ptr.add(self.size) };
        unsafe {
            while addr < end {
                _mm_clflush(addr);
                addr = addr.add(CACHE_LINE);
            }
            _mm_sfence();
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn flush_all(&self) {}

    /// Non-temporal (cache-bypassing) write of a u64 pattern across the region.
    #[cfg(target_arch = "x86_64")]
    pub fn nt_fill_u64(&mut self, pattern: u64) {
        use std::arch::x86_64::{_mm_sfence, _mm_stream_si64};
        let words = self.size / 8;
        let base = self.ptr as *mut i64;
        unsafe {
            for i in 0..words {
                _mm_stream_si64(base.add(i), pattern as i64);
            }
            _mm_sfence();
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn nt_fill_u64(&mut self, pattern: u64) {
        for w in self.as_u64_slice_mut() {
            *w = pattern;
        }
    }
}

impl Drop for MemRegion {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as *mut libc::c_void, self.size);
        }
    }
}
