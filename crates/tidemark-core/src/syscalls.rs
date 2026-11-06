pub fn murmur3_32(data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h: u32 = 0;
    let (chunks, tail) = data.as_chunks::<4>();
    for c in chunks {
        let mut k = u32::from_le_bytes(*c);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let mut k: u32 = 0;
    for (i, b) in tail.iter().enumerate() {
        k |= (*b as u32) << (8 * i);
    }
    if !tail.is_empty() {
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

pub const SYSCALLS: &[(&str, u8)] = &[
    ("sol_invoke_signed_c", 3),
    ("sol_invoke_signed_rust", 3),
    ("sol_set_return_data", 1),
    ("sol_get_return_data", 1),
    ("sol_create_program_address", 1),
    ("sol_try_find_program_address", 1),
    ("sol_get_processed_sibling_instruction", 1),
    ("sol_secp256k1_recover", 1),
    ("abort", 0),
    ("sol_panic_", 0),
    ("sol_log_", 0),
    ("sol_log_64_", 0),
    ("sol_log_compute_units_", 0),
    ("sol_log_pubkey", 0),
    ("sol_log_data", 0),
    ("sol_sha256", 0),
    ("sol_keccak256", 0),
    ("sol_blake3", 0),
    ("sol_poseidon", 0),
    ("sol_curve_validate_point", 0),
    ("sol_curve_group_op", 0),
    ("sol_curve_multiscalar_mul", 0),
    ("sol_curve_pairing_map", 0),
    ("sol_alt_bn128_group_op", 0),
    ("sol_alt_bn128_compression", 0),
    ("sol_big_mod_exp", 0),
    ("sol_get_clock_sysvar", 0),
    ("sol_get_epoch_schedule_sysvar", 0),
    ("sol_get_fees_sysvar", 0),
    ("sol_get_rent_sysvar", 0),
    ("sol_get_last_restart_slot", 0),
    ("sol_get_epoch_rewards_sysvar", 0),
    ("sol_get_sysvar", 0),
    ("sol_get_epoch_stake", 0),
    ("sol_get_stack_height", 0),
    ("sol_remaining_compute_units", 0),
    ("sol_memcpy_", 0),
    ("sol_memmove_", 0),
    ("sol_memcmp_", 0),
    ("sol_memset_", 0),
];

pub fn by_hash(h: u32) -> Option<&'static str> {
    SYSCALLS
        .iter()
        .find(|(n, _)| murmur3_32(n.as_bytes()) == h)
        .map(|(n, _)| *n)
}

pub fn weight(name: &str) -> u8 {
    SYSCALLS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, w)| *w)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn murmur_reference_vectors() {
        assert_eq!(murmur3_32(b""), 0);
        assert_eq!(murmur3_32(b"hello"), 0x248b_fa47);
        assert_eq!(
            murmur3_32(b"The quick brown fox jumps over the lazy dog"),
            0x2e4f_f723
        );
    }
}
