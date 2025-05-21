use sha2::{Digest, Sha256};

// GF(2^8) defines operations over bytes.
// Addition in GF(2^8) is XOR.
#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

// Multiplication in GF(2^8) using the standard irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
// The 0x1B is for the reduction step (0x11B without the x^8 bit).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    while a > 0 && b > 0 {
        if b & 1 == 1 {
            p ^= a;
        }
        if (a & 0x80) != 0 {
            a = (a << 1) ^ 0x1B;
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    p
}

// Exponentiation in GF(2^8) (base^exp) using exponentiation by squaring.
fn gf_pow(base: u8, exp: u8) -> u8 {
    if exp == 0 {
        return 1;
    }
    let mut res: u8 = 1;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            res = gf_mul(res, b);
        }
        b = gf_mul(b, b);
        e >>= 1;
    }
    res
}

// Multiplicative inverse in GF(2^8) using Fermat's Little Theorem: n^(256-2) = n^254.
// n must not be 0.
fn gf_inv(n: u8) -> u8 {
    if n == 0 {
        panic!("Division by zero in GF(2^8): cannot invert 0.");
    }
    gf_pow(n, 254)
}

// Division in GF(2^8) (num / den).
// den must not be 0.
fn gf_div(num: u8, den: u8) -> u8 {
    if den == 0 {
        panic!("Division by zero in GF(2^8): denominator is 0.");
    }
    gf_mul(num, gf_inv(den))
}

// Evaluates a polynomial P(x) = coeffs[k-1]*x^(k-1) + ... + coeffs[1]*x + coeffs[0]
// at a given point x in GF(2^8) using Horner's method.
// coeffs are [a_0, a_1, ..., a_{k-1}].
fn poly_eval_horner(coeffs: &[u8], x: u8) -> u8 {
    let mut res: u8 = 0;
    // Iterate from highest coefficient (coeffs[k-1]) down to constant term (coeffs[0])
    for i in (0..coeffs.len()).rev() {
        res = gf_mul(res, x);
        res = gf_add(res, coeffs[i]);
    }
    res
}

/// Represents a single share.
/// `x` is the x-coordinate (must be non-zero).
/// `ys` is a vector of y-values, one for each byte of the original secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub x: u8,
    pub ys: Vec<u8>,
}

/// Splits a secret into `n` shares, `k` of which are required for reconstruction.
///
/// # Arguments
/// * `secret`: The secret data as a slice of bytes.
/// * `k`: The threshold number of shares required to reconstruct the secret.
/// * `x_coords`: A slice of `n` distinct non-zero `u8` x-coordinates to generate shares for.
///              The length of `x_coords` determines `n`.
///
/// # Returns
/// A `Result` containing a vector of `Share` structs, or an error string if inputs are invalid.
pub fn split_secret(secret: &[u8], k: usize, x_coords: &[u8]) -> Result<Vec<Share>, String> {
    let n = x_coords.len();
    if k == 0 {
        return Err("Threshold k cannot be 0.".to_string());
    }
    if k > n {
        return Err(format!(
            "Threshold k ({}) cannot be greater than number of shares n ({}).",
            k, n
        ));
    }
    if secret.is_empty() {
        return Err("Secret cannot be empty.".to_string());
    }
    if x_coords.iter().any(|&x_val| x_val == 0) {
        return Err("x-coordinates cannot be zero.".to_string());
    }

    let mut sorted_x = x_coords.to_vec();
    sorted_x.sort_unstable();
    if (1..sorted_x.len()).any(|i| sorted_x[i - 1] == sorted_x[i]) {
        return Err("x-coordinates must be distinct.".to_string());
    }

    let mut shares_data: Vec<Share> = Vec::with_capacity(n);
    for &x_val in x_coords {
        shares_data.push(Share {
            x: x_val,
            ys: Vec::with_capacity(secret.len()),
        });
    }

    for &secret_byte in secret {
        let mut coeffs = vec![0u8; k];
        coeffs[0] = secret_byte; // a_0 = S (the secret byte)

        // Generate k-1 random coefficients (a_1, ..., a_{k-1})
        // If k=1, this loop does not run, only a_0 is used.
        if k > 1 {
            let mut hasher = Sha256::new();
            hasher.update(&[secret_byte]);
            hasher.update(&x_coords);
            let result = hasher.finalize();

            for i in 1..k {
                coeffs[i] = result[i % result.len()];
            }
        }

        // For each x_coord, evaluate the polynomial and store the y_value
        for i in 0..n {
            let y_val = poly_eval_horner(&coeffs, shares_data[i].x);
            shares_data[i].ys.push(y_val);
        }
    }
    Ok(shares_data)
}

/// Reconstructs the secret from a given set of shares.
///
/// # Arguments
/// * `shares`: A slice of `Share` structs. At least `k` shares must be provided.
///           If more than `k` shares are provided, only the first `k` are used.
/// * `k`: The original threshold used when splitting the secret.
///
/// # Returns
/// A `Result` containing the reconstructed secret as a `Vec<u8>`, or an error string if inputs are invalid.
pub fn reconstruct_secret(shares: &[Share], k: usize) -> Result<Vec<u8>, String> {
    if k == 0 {
        return Err("Threshold k cannot be 0.".to_string());
    }
    if shares.len() < k {
        return Err(format!(
            "Not enough shares provided (need at least {}, got {}).",
            k,
            shares.len()
        ));
    }
    if shares.is_empty() {
        // This case is covered by shares.len() < k if k > 0
        return Err("Shares list cannot be empty.".to_string());
    }

    // Use only the first k shares for reconstruction.
    let relevant_shares = &shares[0..k];

    let num_bytes_in_secret = relevant_shares[0].ys.len();
    if num_bytes_in_secret == 0 {
        return Err(
            "Shares indicate an empty original secret or are malformed (ys vector is empty)."
                .to_string(),
        );
    }

    let mut distinct_x_coords = Vec::with_capacity(k);
    for share in relevant_shares.iter() {
        if share.x == 0 {
            return Err("Share x-coordinate cannot be zero.".to_string());
        }
        if share.ys.len() != num_bytes_in_secret {
            return Err("All shares used for reconstruction must have the same number of y-values (same secret length).".to_string());
        }
        if distinct_x_coords.contains(&share.x) {
            return Err(
                "x-coordinates of shares used for reconstruction must be distinct.".to_string(),
            );
        }
        distinct_x_coords.push(share.x);
    }

    let mut reconstructed_secret_bytes: Vec<u8> = Vec::with_capacity(num_bytes_in_secret);

    for byte_idx in 0..num_bytes_in_secret {
        let mut current_secret_byte_sum: u8 = 0; // Sum for Lagrange interpolation, starts at 0 (additive identity)

        // Lagrange Interpolation: S = sum( y_j * l_j(0) ) for j = 0 to k-1
        for j in 0..k {
            // For each share_j (x_j, y_j)
            let x_j = relevant_shares[j].x;
            let y_j = relevant_shares[j].ys[byte_idx];

            let mut lagrange_basis_poly_at_0: u8 = 1; // l_j(0), starts at 1 (multiplicative identity)

            // Product part of l_j(0): product( x_m / (x_j - x_m) ) for m != j
            for m in 0..k {
                if m == j {
                    continue;
                }
                let x_m = relevant_shares[m].x;

                // Numerator is x_m
                // Denominator is x_j XOR x_m (since x_j - x_m = x_j + x_m in GF(2^8))
                let num_term = x_m;
                let den_term = gf_add(x_j, x_m);
                // den_term cannot be 0 here if all x_coords in relevant_shares are distinct,
                // which was checked before.

                lagrange_basis_poly_at_0 =
                    gf_mul(lagrange_basis_poly_at_0, gf_div(num_term, den_term));
            }
            current_secret_byte_sum = gf_add(
                current_secret_byte_sum,
                gf_mul(y_j, lagrange_basis_poly_at_0),
            );
        }
        reconstructed_secret_bytes.push(current_secret_byte_sum);
    }
    Ok(reconstructed_secret_bytes)
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;

    pub fn gf_mul_test(a: u8, b: u8) -> u8 {
        gf_mul(a, b)
    }
    pub fn gf_inv_test(n: u8) -> u8 {
        gf_inv(n)
    }
    pub fn poly_eval_horner_test(coeffs: &[u8], x: u8) -> u8 {
        poly_eval_horner(coeffs, x)
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::{gf_inv_test, gf_mul_test, poly_eval_horner_test};
    use super::*;
    use rand::{Rng, seq::SliceRandom};

    #[test]
    fn test_gf_mul_basic() {
        assert_eq!(gf_mul_test(0x53, 0xCA), 0x01); // Example from Wikipedia GF(2^8)
        assert_eq!(gf_mul_test(0x02, 0x80), 0x1B); // 2 * 128 = 256 === x^8. x^8 = x^4+x^3+x+1 = 0x1B
        assert_eq!(gf_mul_test(0xFF, 0xFF), 0x13);
        assert_eq!(gf_mul_test(0x01, 0xAB), 0xAB);
        assert_eq!(gf_mul_test(0x00, 0xAB), 0x00);
    }

    #[test]
    fn test_gf_inv_basic() {
        assert_eq!(gf_inv_test(1), 1);
        assert_eq!(gf_inv_test(0x53), 0xCA);
        assert_eq!(gf_inv_test(0xCA), 0x53);
        assert_eq!(gf_mul_test(0x02, gf_inv_test(0x02)), 0x01);
    }

    #[test]
    #[should_panic]
    fn test_gf_inv_zero() {
        gf_inv_test(0);
    }

    #[test]
    fn test_poly_eval_horner_examples() {
        // P(x) = 3x^2 + 1x + 5
        // coeffs = [5, 1, 3] (a0, a1, a2)
        // In GF(2^8), P(x) = 0x03*x^2 + 0x01*x + 0x05
        // P(0x02):
        // term_2: 0x03 * (0x02*0x02) = 0x03 * 0x04 = 0x0C
        // term_1: 0x01 * 0x02 = 0x02
        // term_0: 0x05
        // Result: 0x0C ^ 0x02 ^ 0x05 = 0x0E ^ 0x05 = 0x0B
        let coeffs = vec![0x05, 0x01, 0x03]; // k=3
        assert_eq!(poly_eval_horner_test(&coeffs, 0x02), 0x0B);

        // P(x) = 0xAA (constant polynomial, k=1)
        // coeffs = [0xAA]
        let coeffs_const = vec![0xAA]; // k=1
        assert_eq!(poly_eval_horner_test(&coeffs_const, 0x10), 0xAA);

        // P(0) should always be coeffs[0]
        assert_eq!(poly_eval_horner_test(&coeffs, 0x00), coeffs[0]);
        assert_eq!(poly_eval_horner_test(&coeffs_const, 0x00), coeffs_const[0]);
    }

    #[test]
    fn test_shamir_e2e_simple() {
        let secret = b"hello world".to_vec();
        let k = 3;
        let x_coords: Vec<u8> = vec![1, 2, 3, 4, 5]; // n=5

        let shares_result = split_secret(&secret, k, &x_coords);
        assert!(shares_result.is_ok());
        let shares = shares_result.unwrap();
        assert_eq!(shares.len(), 5);
        for share in &shares {
            assert_eq!(share.ys.len(), secret.len());
        }

        // Test reconstruction with k shares (e.g., first k shares)
        let chosen_shares_k = shares[0..k].to_vec();
        let reconstructed_k_result = reconstruct_secret(&chosen_shares_k, k);
        assert!(reconstructed_k_result.is_ok());
        assert_eq!(reconstructed_k_result.unwrap(), secret);

        // Test reconstruction with a different set of k shares
        let chosen_shares_k_alt = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let reconstructed_k_alt_result = reconstruct_secret(&chosen_shares_k_alt, k);
        assert!(reconstructed_k_alt_result.is_ok());
        assert_eq!(reconstructed_k_alt_result.unwrap(), secret);

        // Test reconstruction with more than k shares (e.g., all n shares)
        // The reconstruct function should use the first k of the provided.
        let mut rng = rand::rng();
        let mut shuffled_shares = shares.clone();
        shuffled_shares.shuffle(&mut rng); // Shuffle to ensure order doesn't matter for selection

        let reconstructed_all_result = reconstruct_secret(&shuffled_shares, k);
        assert!(reconstructed_all_result.is_ok());
        assert_eq!(reconstructed_all_result.unwrap(), secret);
    }

    #[test]
    fn test_shamir_k_equals_n() {
        let secret = b"k_equals_n_test".to_vec();
        let k = 4;
        let x_coords: Vec<u8> = vec![10, 20, 30, 40]; // n=4

        let shares_result = split_secret(&secret, k, &x_coords);
        assert!(shares_result.is_ok());
        let shares = shares_result.unwrap();
        assert_eq!(shares.len(), k);

        let reconstructed_secret_result = reconstruct_secret(&shares, k);
        assert!(reconstructed_secret_result.is_ok());
        assert_eq!(reconstructed_secret_result.unwrap(), secret);
    }

    #[test]
    fn test_shamir_k1_n1() {
        // Minimum k and n
        let secret = vec![0x42u8]; // Single byte secret
        let k = 1;
        let x_coords: Vec<u8> = vec![1]; // n=1

        let shares_result = split_secret(&secret, k, &x_coords);
        assert!(shares_result.is_ok());
        let shares = shares_result.unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].x, 1);
        // If k=1, P(x) = S (secret byte). So y = S.
        assert_eq!(shares[0].ys[0], secret[0]);

        let reconstructed_secret_result = reconstruct_secret(&shares, k);
        assert!(reconstructed_secret_result.is_ok());
        assert_eq!(reconstructed_secret_result.unwrap(), secret);
    }

    #[test]
    fn test_shamir_k1_n_greater_than_1() {
        let secret = b"S".to_vec();
        let k = 1;
        let x_coords: Vec<u8> = vec![5, 10, 15]; // n=3

        let shares_result = split_secret(&secret, k, &x_coords);
        assert!(shares_result.is_ok());
        let shares = shares_result.unwrap();
        assert_eq!(shares.len(), 3);
        for share in &shares {
            assert_eq!(share.ys[0], secret[0]); // For k=1, all y values are the secret itself
        }

        // Reconstruct with any single share
        let reconstructed_1 = reconstruct_secret(&[shares[0].clone()], k);
        assert_eq!(reconstructed_1.unwrap(), secret);
        let reconstructed_2 = reconstruct_secret(&[shares[1].clone()], k);
        assert_eq!(reconstructed_2.unwrap(), secret);
        let reconstructed_3 = reconstruct_secret(&[shares[2].clone()], k);
        assert_eq!(reconstructed_3.unwrap(), secret);
    }

    #[test]
    fn test_split_invalid_inputs() {
        let secret = b"s".to_vec();
        assert!(split_secret(&secret, 0, &[1]).is_err(), "k=0");
        assert!(split_secret(&secret, 3, &[1, 2]).is_err(), "k > n");
        assert!(split_secret(&[], 1, &[1]).is_err(), "empty secret");
        assert!(split_secret(&secret, 1, &[0]).is_err(), "x_coord = 0");
        assert!(
            split_secret(&secret, 2, &[1, 1]).is_err(),
            "duplicate x_coords"
        );
    }

    #[test]
    fn test_reconstruct_invalid_inputs() {
        let share1 = Share {
            x: 1,
            ys: vec![10, 20],
        };
        let share2 = Share {
            x: 2,
            ys: vec![30, 40],
        };
        let share_malformed_len = Share { x: 3, ys: vec![50] }; // Different ys length
        let share_x_zero = Share {
            x: 0,
            ys: vec![10, 20],
        };
        let share_empty_ys = Share { x: 4, ys: vec![] };

        assert!(
            reconstruct_secret(&[share1.clone(), share2.clone()], 0).is_err(),
            "k=0"
        );
        assert!(
            reconstruct_secret(&[share1.clone()], 2).is_err(),
            "not enough shares"
        );
        assert!(reconstruct_secret(&[], 1).is_err(), "empty shares list");

        // Malformed shares during reconstruction attempt
        assert!(
            reconstruct_secret(&[share1.clone(), share_malformed_len], 2).is_err(),
            "inconsistent ys length"
        );
        assert!(
            reconstruct_secret(&[share1.clone(), share_x_zero], 2).is_err(),
            "share with x=0"
        );
        assert!(
            reconstruct_secret(&[share1.clone(), share_empty_ys], 2).is_err(),
            "share with empty ys"
        );
        assert!(
            reconstruct_secret(&[share1.clone(), share1.clone()], 2).is_err(),
            "duplicate x-coordinates"
        );
    }

    #[test]
    fn test_large_secret() {
        // Test with a larger secret (1000 bytes)
        let mut secret = Vec::with_capacity(1000);
        let mut rng = rand::rng();
        for _ in 0..1000 {
            secret.push(rng.random::<u8>());
        }

        let k = 5;
        let n = 10;
        let mut x_coords = Vec::with_capacity(n);
        for i in 1..=n {
            x_coords.push(i as u8);
        }

        let shares_result = split_secret(&secret, k, &x_coords);
        assert!(shares_result.is_ok());
        let shares = shares_result.unwrap();

        // Select random k shares
        let mut rng = rand::rng();
        let mut indices: Vec<usize> = (0..n).collect();
        indices.shuffle(&mut rng);
        let selected_indices = indices[0..k].to_vec();

        let mut selected_shares = Vec::with_capacity(k);
        for idx in selected_indices {
            selected_shares.push(shares[idx].clone());
        }

        let reconstructed_result = reconstruct_secret(&selected_shares, k);
        assert!(reconstructed_result.is_ok());
        assert_eq!(reconstructed_result.unwrap(), secret);
    }

    #[test]
    fn test_binary_data() {
        // Test with binary data containing all possible byte values
        let mut secret = Vec::with_capacity(256);
        for i in 0..=255u8 {
            secret.push(i);
        }

        let k = 3;
        let n = 5;
        let x_coords: Vec<u8> = (1..=n as u8).collect();

        let shares_result = split_secret(&secret, k, &x_coords);
        assert!(shares_result.is_ok());
        let shares = shares_result.unwrap();

        // Test reconstruction with exactly k shares
        let chosen_shares = shares[1..4].to_vec(); // Take shares 2, 3, 4
        let reconstructed_result = reconstruct_secret(&chosen_shares, k);
        assert!(reconstructed_result.is_ok());
        assert_eq!(reconstructed_result.unwrap(), secret);
    }

    #[test]
    fn test_k_equals_2() {
        // Special case test for k=2 (linear polynomial)
        let secret = b"linear polynomial test".to_vec();
        let k = 2;
        let x_coords: Vec<u8> = vec![1, 2, 3, 4, 5];

        let shares_result = split_secret(&secret, k, &x_coords);
        assert!(shares_result.is_ok());
        let shares = shares_result.unwrap();

        // Try various combinations of 2 shares
        let combinations = vec![vec![0, 1], vec![1, 3], vec![3, 4], vec![0, 4]];

        for combo in combinations {
            let mut selected_shares = Vec::with_capacity(k);
            for &idx in &combo {
                selected_shares.push(shares[idx].clone());
            }

            let reconstructed_result = reconstruct_secret(&selected_shares, k);
            assert!(reconstructed_result.is_ok());
            assert_eq!(reconstructed_result.unwrap(), secret);
        }
    }
}
