"""Benchmark: Memory usage of defense scanning operations.

Uses tracemalloc to measure peak memory allocated during BoundaryDetector
catalogue construction and repeated pattern matching calls.
"""
from __future__ import annotations

import json
import sys
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aumos_owasp_defenses.defenses.asi01_goal_hijack import BoundaryDetector

_ITERATIONS: int = 500

_SAMPLE_TEXT = (
    "The system should process the following user input carefully. "
    "Make sure to validate and sanitise all fields before persisting "
    "to the database. The agent must not reveal its internal state."
)


def bench_boundary_detection_memory() -> dict[str, object]:
    """Benchmark memory usage during repeated boundary detection analysis.

    Returns
    -------
    dict with keys: operation, iterations, peak_memory_kb, current_memory_kb,
    ops_per_second, avg_latency_ms, memory_peak_mb.
    """
    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    detector = BoundaryDetector()

    for _ in range(_ITERATIONS):
        detector.analyze(_SAMPLE_TEXT)

    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot_after.compare_to(snapshot_before, "lineno")
    total_bytes = sum(stat.size_diff for stat in stats if stat.size_diff > 0)
    peak_kb = round(total_bytes / 1024, 2)

    result: dict[str, object] = {
        "operation": "boundary_detection_memory",
        "iterations": _ITERATIONS,
        "peak_memory_kb": peak_kb,
        "current_memory_kb": peak_kb,
        "ops_per_second": 0.0,
        "avg_latency_ms": 0.0,
        "memory_peak_mb": round(peak_kb / 1024, 4),
    }
    print(
        f"[bench_memory_usage] {result['operation']}: "
        f"peak {peak_kb:.2f} KB over {_ITERATIONS} iterations"
    )
    return result


def run_benchmark() -> dict[str, object]:
    """Entry point returning the benchmark result dict."""
    return bench_boundary_detection_memory()


if __name__ == "__main__":
    result = run_benchmark()
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "memory_baseline.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"Results saved to {output_path}")
