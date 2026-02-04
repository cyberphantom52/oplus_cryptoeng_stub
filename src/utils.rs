pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    // Simple pseudo-random generation for stub purposes
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut result = Vec::with_capacity(len);
    let mut state = seed;
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        result.push((state >> 33) as u8);
    }
    result
}
