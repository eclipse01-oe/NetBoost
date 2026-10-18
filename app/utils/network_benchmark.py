import argparse
import csv
import statistics
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TEST_URLS = {
    "google_204": "https://www.google.com/generate_204",
    "cloudflare_trace": "https://www.cloudflare.com/cdn-cgi/trace",
    "example_homepage": "https://example.com/",
}

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_FILE = PROJECT_ROOT / "results" / "network_benchmark.csv"

FIELDS = [
    "timestamp_utc",
    "mode",
    "run",
    "endpoint",
    "url",
    "success",
    "status",
    "ttfb_ms",
    "total_ms",
    "downloaded_bytes",
    "error",
]


def measure_request(url: str) -> dict:
    started = time.perf_counter()

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NetBoost-Benchmark/0.1",
            "Cache-Control": "no-cache",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            headers_received = time.perf_counter()
            body = response.read()
            completed = time.perf_counter()

            return {
                "success": 200 <= response.status < 400,
                "status": response.status,
                "ttfb_ms": round((headers_received - started) * 1000, 2),
                "total_ms": round((completed - started) * 1000, 2),
                "downloaded_bytes": len(body),
                "error": "",
            }

    except urllib.error.HTTPError as exc:
        headers_received = time.perf_counter()
        body = exc.read()
        completed = time.perf_counter()

        return {
            "success": False,
            "status": exc.code,
            "ttfb_ms": round((headers_received - started) * 1000, 2),
            "total_ms": round((completed - started) * 1000, 2),
            "downloaded_bytes": len(body),
            "error": f"HTTP {exc.code}: {exc.reason}",
        }

    except Exception as exc:
        completed = time.perf_counter()

        return {
            "success": False,
            "status": "",
            "ttfb_ms": "",
            "total_ms": round((completed - started) * 1000, 2),
            "downloaded_bytes": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="NetBoost network benchmark")
    parser.add_argument(
        "--mode",
        choices=["direct", "wireguard"],
        required=True,
        help="Label describing the connection being tested",
    )
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()

    if args.runs < 1:
        parser.error("--runs must be at least 1")

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    write_header = not RESULTS_FILE.exists() or RESULTS_FILE.stat().st_size == 0

    summaries = {
        name: {"ttfb": [], "total": []}
        for name in TEST_URLS
    }

    with RESULTS_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)

        if write_header:
            writer.writeheader()

        for run in range(1, args.runs + 1):
            for name, url in TEST_URLS.items():
                result = measure_request(url)

                writer.writerow({
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "mode": args.mode,
                    "run": run,
                    "endpoint": name,
                    "url": url,
                    **result,
                })
                file.flush()

                if result["success"]:
                    summaries[name]["ttfb"].append(result["ttfb_ms"])
                    summaries[name]["total"].append(result["total_ms"])

                status = result["status"] or "ERROR"
                print(
                    f"[{args.mode}] "
                    f"run={run}/{args.runs} "
                    f"endpoint={name} "
                    f"status={status} "
                    f"TTFB={result['ttfb_ms']} ms "
                    f"total={result['total_ms']} ms "
                    f"bytes={result['downloaded_bytes']}"
                )

                if result["error"]:
                    print(f"  Error: {result['error']}")

                time.sleep(0.5)

    print("\n--- Benchmark summary ---")

    for name, metrics in summaries.items():
        if not metrics["ttfb"]:
            print(f"{name}: no successful requests")
            continue

        print(
            f"{name}: "
            f"median TTFB={statistics.median(metrics['ttfb']):.2f} ms, "
            f"median total={statistics.median(metrics['total']):.2f} ms, "
            f"successful runs={len(metrics['ttfb'])}/{args.runs}"
        )

    print(f"\nResults saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    main()
