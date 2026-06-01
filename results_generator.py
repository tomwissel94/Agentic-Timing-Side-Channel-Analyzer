import os
import matplotlib.pyplot as plt

from timing_analyzer import analyze_prefix_timing
from vulnerable_app import vulnerable_check_password, constant_time_check_password


RESULTS_DIR = "results"


def ensure_results_folder():
    """
    Creates the results folder if it does not already exist.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)


def get_correct_prefix_lengths(results):
    """
    Converts guesses into prefix lengths for plotting.

    Example:
    XXXXXXX  -> 0 correct prefix characters
    UXXXXXX  -> 1 correct prefix character
    UGXXXXX  -> 2 correct prefix characters
    UGoTtHE  -> 7 correct prefix characters
    """
    prefix_lengths = []

    for guess, _ in results:
        stripped_guess = guess.rstrip("X")
        prefix_lengths.append(len(stripped_guess))

    return prefix_lengths


def save_graph(results, title, filename):
    """
    Saves a timing graph to the results folder.
    """
    prefix_lengths = get_correct_prefix_lengths(results)
    times_ms = [avg_time * 1000 for _, avg_time in results]

    plt.figure(figsize=(8, 5))
    plt.plot(prefix_lengths, times_ms, marker="o")
    plt.title(title)
    plt.xlabel("Correct Prefix Length")
    plt.ylabel("Average Time (ms)")
    plt.grid(True)

    output_path = os.path.join(RESULTS_DIR, filename)
    plt.savefig(output_path, bbox_inches="tight")
    plt.close()

    print(f"Saved graph: {output_path}")


def save_log(vulnerable_results, fixed_results):
    """
    Saves raw timing results to a text log.
    """
    log_path = os.path.join(RESULTS_DIR, "run_log.txt")

    with open(log_path, "w") as file:
        file.write("=== VULNERABLE FUNCTION RESULTS ===\n\n")

        for guess, timing in vulnerable_results:
            file.write(f"{guess:<10} {timing:.8f} seconds\n")

        file.write("\n\n=== PATCHED CONSTANT-TIME FUNCTION RESULTS ===\n\n")

        for guess, timing in fixed_results:
            file.write(f"{guess:<10} {timing:.8f} seconds\n")

    print(f"Saved log: {log_path}")


def save_summary(vulnerable_results, fixed_results):
    """
    Saves a short human-readable summary of the results.
    """
    vulnerable_start = vulnerable_results[0][1]
    vulnerable_end = vulnerable_results[-1][1]
    vulnerable_difference = vulnerable_end - vulnerable_start

    fixed_start = fixed_results[0][1]
    fixed_end = fixed_results[-1][1]
    fixed_difference = fixed_end - fixed_start

    summary_path = os.path.join(RESULTS_DIR, "summary.txt")

    with open(summary_path, "w") as file:
        file.write("Agentic Timing Side Channel Analyzer\n")
        file.write("=" * 40 + "\n\n")

        file.write("Finding #1: Vulnerable Function\n")
        file.write(
            "The vulnerable password checker shows increasing execution time "
            "as more password characters are correct.\n\n"
        )
        file.write(f"First timing: {vulnerable_start:.8f} seconds\n")
        file.write(f"Last timing: {vulnerable_end:.8f} seconds\n")
        file.write(f"Timing difference: {vulnerable_difference:.8f} seconds\n\n")

        file.write("Finding #2: Patched Function\n")
        file.write(
            "The constant-time comparison reduces the timing trend by avoiding "
            "early return behavior.\n\n"
        )
        file.write(f"First timing: {fixed_start:.8f} seconds\n")
        file.write(f"Last timing: {fixed_end:.8f} seconds\n")
        file.write(f"Timing difference: {fixed_difference:.8f} seconds\n\n")

        file.write("Conclusion\n")
        file.write(
            "The mitigation reduces the timing side channel and makes password "
            "prefix information harder to infer from execution time.\n"
        )

    print(f"Saved summary: {summary_path}")


def main():
    """
    Runs both timing experiments and saves result artifacts.
    """
    ensure_results_folder()

    vulnerable_results = analyze_prefix_timing(vulnerable_check_password)
    fixed_results = analyze_prefix_timing(constant_time_check_password)

    save_graph(
        vulnerable_results,
        "Vulnerable Password Check Timing",
        "vulnerable_timing.png",
    )

    save_graph(
        fixed_results,
        "Constant-Time Password Check Timing",
        "fixed_timing.png",
    )

    save_log(vulnerable_results, fixed_results)
    save_summary(vulnerable_results, fixed_results)

    print("\nResults generated successfully.")


if __name__ == "__main__":
    main()
