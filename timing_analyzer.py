import time
import statistics
import string
from vulnerable_app import vulnerable_check_password, constant_time_check_password


TEST_ALPHABET = string.ascii_letters + string.digits


def measure_time(check_function, guess: str, trials: int = 30) -> float:
    """
    Measures the average runtime of a password check function.
    """
    times = []

    for _ in range(trials):
        start = time.perf_counter()
        check_function(guess)
        end = time.perf_counter()
        times.append(end - start)

    return statistics.mean(times)


def analyze_prefix_timing(check_function, secret_length: int = 7):
    """
    Tests guesses with increasingly correct prefixes.

    A vulnerable function should take longer when more prefix
    characters are correct.
    """
    test_guesses = [
        "X" * secret_length,
        "U" + "X" * (secret_length - 1),
        "UG" + "X" * (secret_length - 2),
        "UGo" + "X" * (secret_length - 3),
        "UGoT" + "X" * (secret_length - 4),
        "UGoTt" + "X" * (secret_length - 5),
        "UGoTtH" + "X" * (secret_length - 6),
        "UGoTtHE",
    ]

    results = []

    for guess in test_guesses:
        avg_time = measure_time(check_function, guess)
        results.append((guess, avg_time))

    return results


def print_results(title: str, results):
    print("\n" + title)
    print("=" * len(title))

    for guess, avg_time in results:
        print(f"Guess: {guess:<10} Average time: {avg_time:.6f} seconds")


def detect_leakage(results) -> bool:
    """
    Simple leakage detector.

    If timing generally increases as more characters are correct,
    the function is likely vulnerable.
    """
    times = [time_value for _, time_value in results]

    increasing_steps = 0

    for i in range(1, len(times)):
        if times[i] > times[i - 1]:
            increasing_steps += 1

    return increasing_steps >= 5


if __name__ == "__main__":
    vulnerable_results = analyze_prefix_timing(vulnerable_check_password)
    print_results("Vulnerable Function Timing Results", vulnerable_results)

    if detect_leakage(vulnerable_results):
        print("\nFinding: Timing leakage detected.")
    else:
        print("\nFinding: No obvious timing leakage detected.")

    fixed_results = analyze_prefix_timing(constant_time_check_password)
    print_results("Constant-Time Function Timing Results", fixed_results)

    if detect_leakage(fixed_results):
        print("\nFinding: Possible timing leakage still detected.")
    else:
        print("\nFinding: Timing leakage reduced or not obvious.")
