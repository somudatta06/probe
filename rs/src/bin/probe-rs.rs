//! probe-rs CLI: selftest, bench, build.

use std::process::exit;
use std::time::Instant;

use probe_rs::{build, build_capture, generate_incident, Loader};

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
        if let Some(rest) = a.strip_prefix(&format!("{}=", flag)) {
            return Some(rest.to_string());
        }
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: probe-rs <selftest|bench|build> [options]");
        exit(2);
    }
    match args[1].as_str() {
        "selftest" => selftest(&args[2..]),
        "bench" => bench(&args[2..]),
        "build" => build_cmd(&args[2..]),
        other => {
            eprintln!("unknown subcommand: {}", other);
            exit(2);
        }
    }
}

fn to_compact(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap()
}

fn selftest(args: &[String]) {
    let n_lines: usize = arg_value(args, "--lines")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);

    let raw = generate_incident(n_lines);
    let raw_bytes = raw.as_bytes();

    let (capsule, capture_id) = build(raw_bytes, 2000);
    let cap_json = to_compact(&capsule);

    // build twice for determinism check
    let (capsule2, capture_id2) = build(raw_bytes, 2000);
    let cap_json2 = to_compact(&capsule2);

    // CLP capture: persist, reopen, and prove the store round-trips losslessly.
    let cache = std::env::temp_dir().join("probe_rs_selftest");
    let cache_s = cache.to_string_lossy().to_string();
    let _ = std::fs::remove_dir_all(&cache);
    let (_capc, cap_id) = build_capture(raw_bytes, 2000, &cache_s);
    let mut ld = Loader::open(&cap_id, &cache_s);
    let recon = ld.all_lines();
    let mut orig: Vec<String> = raw.split('\n').map(|s| s.to_string()).collect();
    if orig.last().map(|s| s.is_empty()).unwrap_or(false) {
        orig.pop();
    }
    let clp_lossless = recon == orig;

    // ---- invariant 1: conservation
    let n_rec = capsule["window"]["records"].as_u64().unwrap() as usize;
    let n_lines_cap = capsule["window"]["lines"].as_u64().unwrap() as usize;
    // recompute cluster counts + covered lines from records via the public API.
    let records = probe_rs::to_records(
        &{
            let text = String::from_utf8_lossy(raw_bytes).into_owned();
            let mut v: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
            if v.last().map(|s| s.is_empty()).unwrap_or(false) {
                v.pop();
            }
            v
        },
    );
    let mut drain = probe_rs::Drain::new(0.4);
    for (i, r) in records.iter().enumerate() {
        drain.add(r, i);
    }
    let sum_counts: usize = drain.clusters.iter().map(|c| c.count).sum();
    let covered: usize = records.iter().map(|r| r.end - r.start + 1).sum();
    let conservation = sum_counts == n_rec && covered == n_lines_cap && n_rec == records.len();

    // ---- invariant 2: determinism
    let determinism = cap_json == cap_json2 && capture_id == capture_id2;

    // ---- invariant 3: redaction
    let redaction = !cap_json.contains("eyJ") && raw.contains("eyJ");

    // ---- invariant 4: never_lose_signal
    let never_lose = cap_json.contains("psycopg2.OperationalError") && cap_json.contains("pool exhausted");

    // ---- invariant 5: multiline_atomic
    // find the psycopg2 fact in evidence; its example must contain a newline.
    let multiline = capsule["evidence"]
        .as_array()
        .map(|facts| {
            facts.iter().any(|f| {
                let ex = f["example"].as_str().unwrap_or("");
                ex.contains("psycopg2.OperationalError") && ex.contains('\n')
            })
        })
        .unwrap_or(false);

    // ---- invariant 6: baseline_shift (some fact has flag went_silent)
    let baseline_shift = capsule["evidence"]
        .as_array()
        .map(|facts| {
            facts.iter().any(|f| {
                f["flags"]
                    .as_array()
                    .map(|fl| fl.iter().any(|x| x.as_str() == Some("went_silent")))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    let checks = [
        ("conservation", conservation),
        ("determinism", determinism),
        ("redaction", redaction),
        ("never_lose_signal", never_lose),
        ("multiline_atomic", multiline),
        ("baseline_shift", baseline_shift),
        ("clp_lossless", clp_lossless),
    ];

    let mut all = true;
    for (name, ok) in checks.iter() {
        println!("{:<20} {}", name, if *ok { "PASS" } else { "FAIL" });
        all &= *ok;
    }
    println!("---");
    println!(
        "lines={} records={} templates={} capsule_tokens={} capture_id={}",
        n_lines_cap,
        n_rec,
        capsule["stats"]["templates"],
        capsule["stats"]["capsule_tokens"],
        capture_id
    );
    // CLP store ratio vs whole-file gzip + a seekability probe.
    let store_path = format!("{}/captures/{}/store.clp", cache_s, cap_id);
    let store_b = std::fs::metadata(&store_path).map(|m| m.len()).unwrap_or(0);
    let gz_b = {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
        e.write_all(raw_bytes).unwrap();
        e.finish().unwrap().len()
    };
    let target = (((n_lines_cap as f64) * 0.851) as usize).max(1);
    let mut ld2 = Loader::open(&cap_id, &cache_s); // fresh: cold cache, honest seek
    let t = Instant::now();
    let _ = ld2.lines(target, target);
    let us = t.elapsed().as_secs_f64() * 1e6;
    println!(
        "CLP store {} KB ({:.1}x) vs whole-file gzip {} KB ({:.1}x)",
        store_b / 1024,
        raw_bytes.len() as f64 / store_b.max(1) as f64,
        gz_b / 1024,
        raw_bytes.len() as f64 / gz_b.max(1) as f64
    );
    println!(
        "seek: context(line {}) decoded {}/{} blocks in {:.1} us",
        target,
        ld2.decoded_blocks(),
        ld2.blocks(),
        us
    );

    println!("{}", if all { "PASS" } else { "FAIL" });
    exit(if all { 0 } else { 1 });
}

fn bench(args: &[String]) {
    let n_lines: usize = arg_value(args, "--lines")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_200_000);

    let raw = generate_incident(n_lines);
    let raw_bytes = raw.as_bytes();
    let actual_lines = raw.split('\n').filter(|_| true).count().saturating_sub(1).max(0);

    let t0 = Instant::now();
    let (capsule, _id) = build(raw_bytes, 2000);
    let elapsed = t0.elapsed();
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;

    let capsule_tokens = capsule["stats"]["capsule_tokens"].as_u64().unwrap();
    let compression_x = capsule["stats"]["compression_x"].as_f64().unwrap();
    let n = capsule["window"]["lines"].as_u64().unwrap();
    let lines_per_sec = n as f64 / elapsed.as_secs_f64();

    let _ = actual_lines;
    println!("n_lines={}", n);
    println!("capsule_tokens={}", capsule_tokens);
    println!("compression_x={}", compression_x);
    println!("elapsed_ms={:.1}", elapsed_ms);
    println!("lines_per_sec={:.0}", lines_per_sec);
}

fn build_cmd(args: &[String]) {
    let file = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| {
            eprintln!("usage: probe-rs build <file> [--budget N]");
            exit(2);
        });
    let budget: usize = arg_value(args, "--budget")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);

    let raw_bytes = std::fs::read(&file).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {}", file, e);
        exit(1);
    });
    let (capsule, _id) = build(&raw_bytes, budget);
    println!("{}", serde_json::to_string_pretty(&capsule).unwrap());
}
