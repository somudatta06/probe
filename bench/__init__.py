"""Calibration + benchmark harness for probe.

  python3 -m bench.grouping     # real LogHub grouping (GA/FGA/FTA/purity) vs Codag's published numbers
  python3 -m bench.diagnosis    # capsule vs raw-truncated vs naive, scored by gold-evidence recall
  python3 -m bench.calibrate    # coordinate search over EvidenceScore weights

Run with the repo root on PYTHONPATH (the `bin/probe` launcher already sets it),
or:  PYTHONPATH=. python3 -m bench.grouping
"""
