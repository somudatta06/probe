//! Port of the 6 capsule invariants as integration tests, on a smaller-scale
//! incident.

use probe_rs::{build, build_capture, generate_incident, to_records, Drain, Loader};

fn raw_lines(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw).into_owned();
    let mut v: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
    if v.last().map(|s| s.is_empty()).unwrap_or(false) {
        v.pop();
    }
    v
}

const N: usize = 2000;

#[test]
fn conservation() {
    let raw = generate_incident(N);
    let (capsule, _) = build(raw.as_bytes(), 2000);
    let n_rec = capsule["window"]["records"].as_u64().unwrap() as usize;
    let n_lines = capsule["window"]["lines"].as_u64().unwrap() as usize;

    let records = to_records(&raw_lines(raw.as_bytes()));
    let mut drain = Drain::new(0.4);
    for (i, r) in records.iter().enumerate() {
        drain.add(r, i);
    }
    let sum_counts: usize = drain.clusters.iter().map(|c| c.count).sum();
    let covered: usize = records.iter().map(|r| r.end - r.start + 1).sum();

    assert_eq!(sum_counts, n_rec, "sum cluster counts == n_records");
    assert_eq!(covered, n_lines, "covered lines == n_lines");
    assert_eq!(n_rec, records.len());
}

#[test]
fn determinism() {
    let raw = generate_incident(N);
    let (c1, id1) = build(raw.as_bytes(), 2000);
    let (c2, id2) = build(raw.as_bytes(), 2000);
    assert_eq!(
        serde_json::to_string(&c1).unwrap(),
        serde_json::to_string(&c2).unwrap()
    );
    assert_eq!(id1, id2);
}

#[test]
fn redaction() {
    let raw = generate_incident(N);
    let (capsule, _) = build(raw.as_bytes(), 2000);
    let js = serde_json::to_string(&capsule).unwrap();
    assert!(raw.contains("eyJ"), "raw must contain the JWT");
    assert!(!js.contains("eyJ"), "capsule must not contain the JWT");
}

#[test]
fn never_lose_signal() {
    let raw = generate_incident(N);
    let (capsule, _) = build(raw.as_bytes(), 2000);
    let js = serde_json::to_string(&capsule).unwrap();
    assert!(js.contains("psycopg2.OperationalError"));
    assert!(js.contains("pool exhausted"));
}

#[test]
fn multiline_atomic() {
    let raw = generate_incident(N);
    let (capsule, _) = build(raw.as_bytes(), 2000);
    let found = capsule["evidence"].as_array().unwrap().iter().any(|f| {
        let ex = f["example"].as_str().unwrap_or("");
        ex.contains("psycopg2.OperationalError") && ex.contains('\n')
    });
    assert!(found, "psycopg2 fact example must contain a newline");
}

#[test]
fn baseline_shift() {
    let raw = generate_incident(N);
    let (capsule, _) = build(raw.as_bytes(), 2000);
    let found = capsule["evidence"].as_array().unwrap().iter().any(|f| {
        f["flags"]
            .as_array()
            .map(|fl| fl.iter().any(|x| x.as_str() == Some("went_silent")))
            .unwrap_or(false)
    });
    assert!(found, "some fact must carry went_silent");
}

#[test]
fn corrupt_store_no_panic() {
    let raw = generate_incident(N);
    let cache = std::env::temp_dir().join("probe_rs_corrupt");
    let cs = cache.to_string_lossy().to_string();
    let _ = std::fs::remove_dir_all(&cache);
    let (_c, id) = build_capture(raw.as_bytes(), 2000, &cs);
    // truncate/corrupt the store; decoding must degrade gracefully, never panic.
    std::fs::write(format!("{}/captures/{}/store.clp", cs, id), vec![0u8, 1, 2, 3, 4, 5]).unwrap();
    let mut ld = Loader::open(&id, &cs);
    let _ = ld.all_lines();
    let _ = ld.verify("F0");
}

#[test]
fn clp_lossless() {
    let raw = generate_incident(N);
    let cache = std::env::temp_dir().join("probe_rs_test_clp");
    let cs = cache.to_string_lossy().to_string();
    let _ = std::fs::remove_dir_all(&cache);
    let (_c, id) = build_capture(raw.as_bytes(), 2000, &cs);
    let mut ld = Loader::open(&id, &cs);
    let recon = ld.all_lines();
    let orig = raw_lines(raw.as_bytes());
    assert_eq!(recon, orig, "CLP store decodes byte-for-byte to the original lines");
    // soundness over the store: verify the psycopg2 fact re-derives.
    let fid = ld.capsule()["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["example"].as_str().unwrap_or("").contains("psycopg2"))
        .map(|f| f["fact_id"].as_str().unwrap().to_string())
        .expect("a psycopg2 fact");
    let v = ld.verify(&fid);
    assert_eq!(v["matches"], serde_json::json!(true));
}
