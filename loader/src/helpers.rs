use core::sync::atomic::{compiler_fence, Ordering};

// Abusing fnv1a hash to find the string we're looking for
// Can't just do a string comparison because the segments aren't properly loaded yet
#[inline(never)]
pub const fn fnv1a_hash_32_wstr(wchars: &[u16]) -> u32 {
	const FNV_OFFSET_BASIS_32: u32 = 0x811c9dc5;
	const FNV_PRIME_32: u32 = 0x01000193;

	let mut hash = FNV_OFFSET_BASIS_32;

	let mut i = 0;
	while i < wchars.len() {
		hash ^= wchars[i] as u32;
		hash = hash.wrapping_mul(FNV_PRIME_32);
		i += 1;
	}
	hash
}

// Abusing fnv1a hash to find the string we're looking for
// Can't just do a string comparison because the segments aren't properly loaded yet
#[inline(never)]
pub const fn fnv1a_hash_32(chars: &[u8]) -> u32 {
	const FNV_OFFSET_BASIS_32: u32 = 0x811c9dc5;
	const FNV_PRIME_32: u32 = 0x01000193;

	let mut hash = FNV_OFFSET_BASIS_32;

	let mut i = 0;
	while i < chars.len() {
		hash ^= chars[i] as u32;
		hash = hash.wrapping_mul(FNV_PRIME_32);
		i += 1;
	}
	hash
}

#[inline(never)]
pub fn simple_memcpy(dest: *mut u8, src: *mut u8, len: usize) {
	let n_bytes = len; // Iterate backwards to avoid optimizing..?
	for i in (0..n_bytes).rev() {
		compiler_fence(Ordering::Acquire);
		unsafe { *dest.add(i) = *src.add(i) };
	}
}
