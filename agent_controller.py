from vulnerable_app import vulnerable_check_password, constant_time_check_password
from timing_analyzer import analyze_prefix_timing, print_results, detect_leakage
from constant_time_patch import explain_patch


def agent_step(step_number: int, message: str):
    print(f"\n[Agent Step {step_number}] {message}")


def main():
    agent_step(1, "Inspecting the target password-checking function.")
    print("Target function: vulnerable_check_password()")
    print("Hypothesis: The function may leak timing information due to early return behavior.")

    agent_step(2, "Running timing measurements on the vulnerable function.")
    vulnerable_results = analyze_prefix_timing(vulnerable_check_password)
    print_results("Vulnerable Function Timing Results", vulnerable_results)

    agent_step(3, "Analyzing timing trend.")
    vulnerable_leak = detect_leakage(vulnerable_results)

    if vulnerable_leak:
        print("Conclusion: Timing side channel detected.")
        print("Reason: Runtime generally increases as more prefix characters are correct.")
    else:
        print("Conclusion: No obvious timing side channel detected.")

    agent_step(4, "Generating mitigation.")
    print(explain_patch())

    agent_step(5, "Testing the constant-time patched function.")
    fixed_results = analyze_prefix_timing(constant_time_check_password)
    print_results("Constant-Time Function Timing Results", fixed_results)

    agent_step(6, "Comparing before and after results.")
    fixed_leak = detect_leakage(fixed_results)

    if vulnerable_leak and not fixed_leak:
        print("Final result: The patch reduced the timing side channel.")
    elif vulnerable_leak and fixed_leak:
        print("Final result: The vulnerable version leaked timing, but the patched version may need more testing.")
    else:
        print("Final result: No strong leakage detected in this run.")

    agent_step(7, "Project summary.")
    print("""
This agentic workflow tested a password checker, measured execution time,
identified timing leakage, recommended a constant-time comparison, and retested
the fixed version. This demonstrates how an AI-assisted security pipeline can
analyze and improve software against timing side-channel vulnerabilities.
""")


if __name__ == "__main__":
    main()


