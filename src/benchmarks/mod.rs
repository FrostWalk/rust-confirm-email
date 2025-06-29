//! Benchmarks for performance testing
//! 
//! These benchmarks help measure the performance characteristics of the
//! email confirmation token system.
//! 
//! **Running benchmarks:**
//! - `cargo test bench_ -- --ignored --nocapture` - Run all benchmarks (may take time)
//! - `cargo test bench_fast` - Run only the fast benchmarks
//! - `cargo test performance_smoke_test` - Quick performance check
//! 
//! **Note:** Argon2 is intentionally slow (3+ seconds per operation) for security.
//! This is normal and expected behavior for password-based key derivation.

use crate::{generate_token, generate_token_with_expiration, validate_token};
use std::time::{Duration, Instant};

const BENCHMARK_EMAIL: &str = "benchmark@example.com";
const BENCHMARK_KEY: &str = "benchmark_encryption_key_123";
const ITERATIONS: usize = 10; // Reduced from 1000 to 10 for faster execution

/// Fast benchmark that runs with regular tests
#[test]
fn bench_fast_single_operation() {
    let start = Instant::now();
    
    let token = generate_token(BENCHMARK_EMAIL.to_string(), BENCHMARK_KEY.to_string())
        .expect("Token generation failed");
    let generation_time = start.elapsed();
    
    let start = Instant::now();
    let _email = validate_token(token, BENCHMARK_KEY.to_string())
        .expect("Token validation failed");
    let validation_time = start.elapsed();
    
    println!("Fast benchmark results:");
    println!("  Token generation: {:?}", generation_time);
    println!("  Token validation: {:?}", validation_time);
    println!("  Round-trip total: {:?}", generation_time + validation_time);
}

#[test]
#[ignore] // Use `cargo test bench_ -- --ignored` to run benchmarks
fn bench_token_generation() {
    let start = Instant::now();
    
    for _ in 0..ITERATIONS {
        let _token = generate_token(BENCHMARK_EMAIL.to_string(), BENCHMARK_KEY.to_string())
            .expect("Token generation failed");
    }
    
    let duration = start.elapsed();
    let avg_time = duration / ITERATIONS as u32;
    
    println!("Token generation benchmark:");
    println!("  Total time: {:?}", duration);
    println!("  Average time per token: {:?}", avg_time);
    println!("  Tokens per second: {:.2}", 1000.0 / avg_time.as_millis() as f64 * 1000.0);
}

#[test]
#[ignore]
fn bench_token_validation() {
    // Pre-generate tokens for validation benchmark
    let mut tokens = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let token = generate_token(BENCHMARK_EMAIL.to_string(), BENCHMARK_KEY.to_string())
            .expect("Token generation failed");
        tokens.push(token);
    }
    
    let start = Instant::now();
    
    for token in tokens {
        let _email = validate_token(token, BENCHMARK_KEY.to_string())
            .expect("Token validation failed");
    }
    
    let duration = start.elapsed();
    let avg_time = duration / ITERATIONS as u32;
    
    println!("Token validation benchmark:");
    println!("  Total time: {:?}", duration);
    println!("  Average time per validation: {:?}", avg_time);
    println!("  Validations per second: {:.2}", 1000.0 / avg_time.as_millis() as f64 * 1000.0);
}

#[test]
#[ignore]
fn bench_round_trip() {
    let start = Instant::now();
    
    for _ in 0..ITERATIONS {
        let token = generate_token(BENCHMARK_EMAIL.to_string(), BENCHMARK_KEY.to_string())
            .expect("Token generation failed");
        let _email = validate_token(token, BENCHMARK_KEY.to_string())
            .expect("Token validation failed");
    }
    
    let duration = start.elapsed();
    let avg_time = duration / ITERATIONS as u32;
    
    println!("Round-trip (generate + validate) benchmark:");
    println!("  Total time: {:?}", duration);
    println!("  Average time per round-trip: {:?}", avg_time);
    println!("  Round-trips per second: {:.2}", 1000.0 / avg_time.as_millis() as f64 * 1000.0);
}

#[test]
#[ignore]
fn bench_different_expiration_times() {
    let expiration_times = vec![60, 3600]; // Reduced to just 2 test cases: 1min, 1hr
    let test_iterations = 5; // Much smaller number for this test
    
    for exp_time in expiration_times {
        let start = Instant::now();
        
        for _ in 0..test_iterations {
            let _token = generate_token_with_expiration(
                BENCHMARK_EMAIL.to_string(), 
                BENCHMARK_KEY.to_string(), 
                exp_time
            ).expect("Token generation failed");
        }
        
        let duration = start.elapsed();
        let avg_time = duration / test_iterations as u32;
        
        println!("Token generation with {}s expiration:", exp_time);
        println!("  Average time: {:?}", avg_time);
    }
}

#[test]
#[ignore]
fn bench_concurrent_generation() {
    use std::thread;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    
    let thread_count = 2; // Reduced from 4 to 2
    let iterations_per_thread = ITERATIONS / thread_count;
    let counter = Arc::new(AtomicUsize::new(0));
    
    let start = Instant::now();
    
    let handles: Vec<_> = (0..thread_count).map(|_| {
        let counter = Arc::clone(&counter);
        thread::spawn(move || {
            for _ in 0..iterations_per_thread {
                let _token = generate_token(BENCHMARK_EMAIL.to_string(), BENCHMARK_KEY.to_string())
                    .expect("Token generation failed");
                counter.fetch_add(1, Ordering::Relaxed);
            }
        })
    }).collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let duration = start.elapsed();
    let total_generated = counter.load(Ordering::Relaxed);
    let avg_time = duration / total_generated as u32;
    
    println!("Concurrent token generation benchmark ({} threads):", thread_count);
    println!("  Total tokens generated: {}", total_generated);
    println!("  Total time: {:?}", duration);
    println!("  Average time per token: {:?}", avg_time);
    println!("  Tokens per second: {:.2}", total_generated as f64 / duration.as_secs_f64());
}

#[test]
#[ignore]
fn bench_memory_usage() {
    // Simple test to check if token size grows with different inputs
    let test_cases = vec![
        ("short@x.co", "shortkey"),
        ("medium.length.email@example.com", "medium_length_encryption_key"),
        ("very.long.email.address.for.testing@very-long-domain-name-example.com", 
         "very_long_encryption_key_for_testing_purposes_with_lots_of_characters"),
    ];
    
    for (email, key) in test_cases {
        let token = generate_token(email.to_string(), key.to_string())
            .expect("Token generation failed");
        
        println!("Email: {} ({}bytes), Key: {} ({}bytes) -> Token: {}bytes", 
                 email, email.len(), 
                 key, key.len(),
                 token.len());
    }
}

/// Simple performance test that can be run with regular `cargo test`
#[test]
fn performance_smoke_test() {
    let iterations = 10; // Reduced number for faster test execution
    
    let start = Instant::now();
    
    for i in 0..iterations {
        let email = format!("user{}@example.com", i);
        let token = generate_token(email.clone(), BENCHMARK_KEY.to_string())
            .expect("Token generation failed");
        let validated_email = validate_token(token, BENCHMARK_KEY.to_string())
            .expect("Token validation failed");
        assert_eq!(email, validated_email);
    }
    
    let duration = start.elapsed();
    
    // More realistic performance threshold for crypto operations with Argon2
    // Argon2 is computationally expensive by design for security
    let max_avg_time = Duration::from_millis(5000); // 5 seconds per round-trip for crypto ops
    let avg_time = duration / iterations;
    
    assert!(avg_time < max_avg_time, 
            "Performance regression: average round-trip time {}ms exceeds threshold {}ms",
            avg_time.as_millis(), max_avg_time.as_millis());
    
    println!("Performance smoke test passed: {}ms average round-trip time", 
             avg_time.as_millis());
} 