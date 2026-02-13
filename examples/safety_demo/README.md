# Leadership Safety Demo

This folder now contains two demos for leadership presentations.

## Demo 1: Fast before/after (3-5 min)

Shows the same agent behavior with and without Tollgate.

Run:

```bash
# Run from this folder
python demo.py
```

Use this when you need a fast narrative around risk reduction.

## Demo 2: Full safety stack (10-15 min)

Shows concrete examples for all major safety controls and ends with a scorecard.

Run:

```bash
# Run from this folder
python full_safety_demo.py
```

This includes examples for:

1. Manifest signing and tamper detection
2. Agent identity signing and spoofing prevention
3. Policy + approval + grants (controlled autonomy)
4. Safe default DENY for unknown tools/effects
5. Parameter schema validation
6. Global network policy + per-tool URL constraints
7. Rate limiting
8. Circuit breaker
9. Multi-agent delegation controls
10. Context integrity monitoring
11. Anomaly detection on audit stream
12. Immutable audit chain verification (if encryption extras installed)
13. Field-level encrypted audit logs (if encryption extras installed)
14. Policy regression testing
15. Persistent grant storage with SQLite

## Files

- `demo.py`: Fast before/after narrative
- `manifest.yaml`, `policy.yaml`: Inputs for fast demo
- `full_safety_demo.py`: Entry point for the complete safety demo
- `full_safety_demo_core.py`: Core implementation for the complete safety demo
- `full_manifest.yaml`, `full_policy.yaml`, `full_scenarios.yaml`: Inputs for the complete safety demo
- `audit.jsonl`, `full_safety_audit.jsonl`, `full_immutable_audit.jsonl`: Generated evidence logs
