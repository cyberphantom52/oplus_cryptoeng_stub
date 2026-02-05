use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    // Simple pseudo-random generation for stub purposes
    // Use a fallback seed if time retrieval fails
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_else(|_| {
            // If system time is before UNIX_EPOCH, use a fixed seed
            // combined with the length to provide some variation
            0xDEADBEEF_CAFEBABE ^ (len as u64)
        });

    let mut result = Vec::with_capacity(len);
    let mut state = seed;
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        result.push((state >> 33) as u8);
    }
    result
}
