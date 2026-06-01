import os
import matplotlib.pyplot as plt
from timing_analyzer import analyze_prefix_timing
from vulnerable_app import (
    vulnerable_check_password,
    constant_time_check_password
)

RESULTS_DIR = "results"


def ensure_results_folder():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def save_graph(results, title, filename):
    labels = []
    times = []

    for guess, avg_time in results:
        labels.append(str(len(guess.rstrip("X"))))
        times.append(avg_time * 1000)

    plt.figure(figsize=(8, 5))
    plt.plot(range(len(times)), times, marker="o")
    plt.title(title)
    plt.xlabel("Correct Prefix Length")
    plt.ylabel("Average Time (ms)")
    plt.grid(True)

    plt.savefig(os.path.join(RESULTS_DIR, filename))
    plt.close()


def save_log(vulnerable_results, fixed_results):
    log_path = os.path.join(RESULTS_DIR, "run_log.txt")

    with open(log_path, "w") as f:

        f.write("=== VULNERABLE RESULTS ===\n\n")

        for guess, timing in vulnerable_results:
            f.write(
                f"{guess:<10} "
                f"{timing:.8f} seconds\n"
            )

        f.write("\n\n")

        f.write("=== PATCHED RESULTS ===\n\n")

        for guess, timing in fixed_results:
            f.write(
                f"{guess:<10} "
                f"{timing:.8f} seconds\n"
            )


def save_summary(vulnerable_results, fixed_results):

    vulnerable_start = vulnerable_results[0][1]
    vulnerable_end = vulnerable_results[-1][1]

    fixed_start = fixed_results[0][1]
    fixed_end = fixed_results[-1][1]

    summary_path = os.path.join(
        RESULTS_DIR,
        "summary.txt"
    )

    with open(summary_path, "w") as f:

        f.write("Agentic Timing Side Channel Analyzer\n")
        f.write("=" * 40 + "\n\n")

        f.write(
            "Finding #1:\n"
            "The vulnerable password checker "
            "shows increasing execution time "
            "as more password characters are correct.\n\n"
        )

        f.write(
            f"First timing: {vulnerable_start:.8f}\n"
        )

        f.write(
            f"Last timing: {vulnerable_end:.8f}\n\n"
        )

        f.write(
            "Finding #2:\n"
            "The constant-time comparison "
            "significantly reduces the timing trend.\n\n"
        )

        f.write(
            f"First timing: {fixed_start:.8f}\n"
        )

        f.write(
            f"Last timing: {fixed_end:.8f}\n\n"
        )

        f.write(
            "Conclusion:\n"
            "The mitigation reduces the timing "
            "side channel and makes password "
            "length/prefix information harder "
            "to infer from execution time.\n"
        )


def main():

    ensure_results_folder()

    vulnerable_results = analyze_prefix_timing(
        vulnerable_check_password
    )

    fixed_results = analyze_prefix_timing(
        constant_time_check_password
    )

    save_graph(
        vulnerable_results,
        "Vulnerable Password Check",
        "vulnerable_timing.png"
    )

    save_graph(
        fixed_results,
        "Constant-Time Password Check",
        "fixed_timing.png"
    )

    save_log(
        vulnerable_results,
        fixed_results
    )

    save_summary(
        vulnerable_results,
        fixed_results
    )

    print("Results generated successfully.")


if __name__ == "__main__":
    main()
