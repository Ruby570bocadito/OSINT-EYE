"""Standalone benchmark runner for OSINT EYE core.

Usage (from the repo root or anywhere):

    python tests/bench/bench_runner.py [--rounds N] [--json PATH] [--list]

What it does
============
* Measures each case in ``bench_cases.py`` offline on synthetic data.
* Reports ops/sec (median across rounds) per case.
* Compares every case against its generous floor in ``floors.json``;
  a case that drops below its floor signals a gross performance
  regression and makes the runner exit with code 1.
* Never runs as part of the pytest suite (``bench_*`` files are not
  collected); run it on demand, e.g. before releasing a hot refactor.

Floors are recorded on development hardware with a wide safety margin
(so slower machines still pass): they catch 10-100x degradations, not
millisecond noise.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.bench.bench_cases import BenchCase, build_cases  # noqa: E402

FLOORS_PATH = _HERE / "floors.json"
DEFAULT_ROUNDS = 5
WARMUP_FRACTION = 0.2  # one warmup round at ~20% of the real iterations


def load_floors() -> dict[str, float]:
    if not FLOORS_PATH.exists():
        return {}
    data = json.loads(FLOORS_PATH.read_text(encoding="utf-8"))
    return {str(k): float(v) for k, v in data.items()}


def measure(case: BenchCase, rounds: int) -> list[float]:
    """Return the ops/sec observed per round (warmup excluded)."""
    ctx = case.setup()
    warmup = max(1, int(case.iters * WARMUP_FRACTION))
    for i in range(warmup):
        case.run(ctx, i)

    rates: list[float] = []
    for _round_index in range(rounds):
        start = time.perf_counter()
        for i in range(case.iters):
            case.run(ctx, i)
        elapsed = time.perf_counter() - start
        rates.append(case.iters / elapsed if elapsed > 0 else float("inf"))
    return rates


def fmt(value: float) -> str:
    if value >= 1000:
        return f"{value:,.0f}"
    if value >= 1:
        return f"{value:,.1f}"
    return f"{value:.4f}"


def run_all(rounds: int) -> tuple[list[dict[str, Any]], bool]:
    floors = load_floors()
    rows: list[dict[str, Any]] = []
    ok = True

    print(f"OSINT EYE benchmarks — {rounds} rounds por caso (offline, sintético)\n")
    header = f"{'caso':<24}{'ops/sec (mediana)':>20}{'min':>16}{'suelo':>14}{'estado':>10}"
    print(header)
    print("-" * len(header))

    for case in build_cases():
        rates = measure(case, rounds)
        median = statistics.median(rates)
        floor = floors.get(case.name)
        status = "—"
        if floor is not None:
            if median < floor:
                status = "REGRESION"
                ok = False
            else:
                status = "ok"
        rows.append(
            {
                "case": case.name,
                "ops_sec_median": median,
                "ops_sec_min": min(rates),
                "ops_sec_max": max(rates),
                "rounds": rounds,
                "iters": case.iters,
                "floor": floor,
                "status": status,
            }
        )
        floor_txt = fmt(floor) if floor is not None else "n/d"
        print(
            f"{case.name:<24}{fmt(median):>20}{fmt(min(rates)):>16}"
            f"{floor_txt:>14}{status:>10}"
        )

    print("\nSuelos en floors.json (márgenes generosos): detectan degradaciones")
    print("groseras (10-100x), no ruido de milisegundos. Un caso sin suelo se")
    print("informa como n/d y no afecta al código de salida.")
    return rows, ok


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmarks offline de OSINT EYE")
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    parser.add_argument("--json", type=str, default="", help="volcar resultados a PATH")
    parser.add_argument("--list", action="store_true", help="listar casos y salir")
    args = parser.parse_args()

    cases = build_cases()
    if args.list:
        for case in cases:
            print(f"{case.name:<24}{case.iters:>8} iters  {case.description}")
        return 0

    rows, ok = run_all(args.rounds)
    if args.json:
        Path(args.json).write_text(
            json.dumps({"benchmarks": rows}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\nResultados volcados a {args.json}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
