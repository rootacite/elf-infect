// demo.rs
// Generate 1000 random integers, sort them with heap sort, print to stdout.

use std::io::{self, Write, BufWriter};
use std::time::{SystemTime, UNIX_EPOCH};

/// Simple xorshift64 RNG
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let s = if seed == 0 { 0x9E3779B97F4A7C15u64 } else { seed };
        XorShift64 { state: s }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    #[inline]
    fn next_i64_range(&mut self, range: i64) -> i64 {
        if range <= 0 {
            return 0;
        }
        (self.next_u64() % (range as u64)) as i64
    }
}

/// In-place heap sort for i64 slice
fn heapsort(a: &mut [i64]) {
    let n = a.len();
    if n <= 1 {
        return;
    }

    fn sift_down(a: &mut [i64], start: usize, end: usize) {
        let mut root = start;
        loop {
            let left = root * 2 + 1;
            if left > end {
                break;
            }
            let mut swap = root;

            if a[swap] < a[left] {
                swap = left;
            }
            let right = left + 1;
            if right <= end && a[swap] < a[right] {
                swap = right;
            }

            if swap == root {
                return;
            }

            a.swap(root, swap);
            root = swap;
        }
    }

    // Build heap
    let mut start = n / 2;
    while start > 0 {
        start -= 1;
        sift_down(a, start, n - 1);
        if start == 0 {
            break;
        }
    }

    // Extract elements
    let mut end = n - 1;
    while end > 0 {
        a.swap(0, end);
        sift_down(a, 0, end - 1);
        end -= 1;
    }
}

#[no_mangle]
pub extern "C" fn rs_main() -> i32 {
    const COUNT: usize = 1000;

    // Seed from system time
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);

    let mut rng = XorShift64::new(seed);

    // Allocate vector on heap
    let mut v: Vec<i64> = Vec::with_capacity(COUNT);
    for _ in 0..COUNT {
        v.push(rng.next_i64_range(1_000_000));
    }

    // Sort
    heapsort(&mut v);

    // Output
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for val in v.iter() {
        writeln!(out, "{}", val).unwrap();
    }
    out.flush().unwrap();

    0
}
