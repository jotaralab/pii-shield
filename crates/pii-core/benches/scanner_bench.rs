use pii_core::{PiiCatalog, PiiScanner, PiiSessionVault, SecurityPolicy, StreamingRehydrator};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    println!("=== PII-SHIELD LATENCY BENCHMARKS ===");

    let catalog = PiiCatalog::with_locales(&["global", "id", "us", "eu", "sg"]).expect("Catalog load");
    let scanner = PiiScanner::from_catalog(&catalog).expect("Scanner build");
    let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);

    let sample_prompt = "Mohon transfer dana sebesar Rp 5.000.000 ke rekening IBAN DE89370400440532013000 atas nama Budi Santoso dengan NIK 3573012203950001, NPWP 01.234.567.8-123.000, nomor HP 081234567890, dan kartu kredit 4532-0151-1283-0366.";

    // 1. Scanner benchmark
    let iterations = 10_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let matches = scanner.scan(black_box(sample_prompt));
        black_box(matches);
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / iterations;
    println!("Single-pass Scan Latency (5 entities): {:?} per op", per_op);
    assert!(
        per_op.as_micros() < 2000,
        "Scanner latency exceeded budget: {:?}",
        per_op
    );

    // 2. Vault Redact benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let redacted = vault.redact(black_box(sample_prompt));
        black_box(redacted);
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / iterations;
    println!("Vault Redact Latency: {:?} per op", per_op);

    // 3. Streaming Rehydrator benchmark
    let scrubbed = vault.redact(sample_prompt);
    let start = Instant::now();
    for _ in 0..iterations {
        let mut stream = StreamingRehydrator::new();
        let chunk1 = stream.push_chunk(black_box(&scrubbed[..scrubbed.len() / 2]), &vault);
        let chunk2 = stream.push_chunk(black_box(&scrubbed[scrubbed.len() / 2..]), &vault);
        let flush = stream.flush(&vault);
        black_box((chunk1, chunk2, flush));
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / iterations;
    println!("Streaming Rehydration Latency: {:?} per op", per_op);

    println!("All benchmark smoke tests passed successfully!");
}
