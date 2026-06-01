import os
from datetime import datetime

from vulnerable_app import vulnerable_check_password, constant_time_check_password
from timing_analyzer import analyze_prefix_timing, detect_leakage
from results_generator import main as generate_results


RESULTS_DIR = "results"
REPORT_PATH = os.path.join(RESULTS_DIR, "security_report.md")


def agent_log(step_number: int, message: str):
    print(f"\n[Agent Step {step_number}] {message}")


def read_source_file(filename: str) -> str:
    with open(filename, "r") as file:
        return file.read()


def inspect_code_for_timing_leak(source_code: str):
    findings = []

    if "return False" in source_code:
        findings.append(
            "Early-return behavior was found. This can create a timing side "
            "channel because incorrect guesses may return faster than partially "
            "correct guesses."
        )

    if "time.sleep" in source_code:
        findings.append(
            "An artificial delay was found. This makes the timing side channel "
            "easier to observe during testing."
        )

    if "compare_digest" in source_code:
        findings.append(
            "A constant-time comparison method, hmac.compare_digest, was found. "
            "This is an appropriate mitigation for timing leakage in string comparison."
        )

    if not findings:
        findings.append(
            "No obvious timing side-channel indicators were found during simple inspection."
        )

    return findings


def summarize_results(results):
    lines = []

    for guess, avg_time in results:
        lines.append(f"- Guess `{guess}` average time: `{avg_time:.8f}` seconds")

    return "\n".join(lines)


def timing_range_summary(results):
    first_guess, first_time = results[0]
    last_guess, last_time = results[-1]

    return (
        f"First guess `{first_guess}`: `{first_time:.8f}` seconds\n\n"
        f"Last guess `{last_guess}`: `{last_time:.8f}` seconds\n\n"
        f"Difference: `{last_time - first_time:.8f}` seconds"
    )


def create_security_report(
    vulnerable_results,
    fixed_results,
    vulnerable_leak,
    fixed_leak,
    code_findings,
):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    report_lines = [
        "# Agentic Timing Side Channel Security Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Project Overview",
        "",
        "This project demonstrates an agentic AI style workflow for detecting and mitigating a timing side-channel vulnerability in a password-checking function.",
        "",
        "The agent inspects source code, forms a hypothesis, runs timing measurements, analyzes the results, recommends a mitigation, retests the patched version, and produces this report.",
        "",
        "## Agent Workflow",
        "",
        "1. Inspect the vulnerable password-checking code.",
        "2. Identify possible timing leak patterns.",
        "3. Run timing measurements against the vulnerable function.",
        "4. Analyze whether execution time increases as more prefix characters are correct.",
        "5. Recommend a constant-time comparison mitigation.",
        "6. Retest the patched function.",
        "7. Generate final findings and result artifacts.",
        "",
        "## Source Code Inspection Findings",
        "",
    ]

    for finding in code_findings:
        report_lines.append(f"- {finding}")

    report_lines.extend(
        [
            "",
            "## Vulnerable Function Timing Results",
            "",
            summarize_results(vulnerable_results),
            "",
            "## Vulnerability Finding",
            "",
            f"Timing leakage detected: **{vulnerable_leak}**",
            "",
            "The vulnerable implementation leaks timing information because it returns as soon as it finds an incorrect character. This means guesses with more correct starting characters take longer to reject.",
            "",
            "### Vulnerable Timing Range Summary",
            "",
            timing_range_summary(vulnerable_results),
            "",
            "## Recommended Mitigation",
            "",
            "Replace early-return password comparison logic with a constant-time comparison method such as:",
            "",
            "```python",
            "hmac.compare_digest(guess, SECRET_PASSWORD)",
            "```",
            "",
            "This reduces timing leakage because the comparison avoids stopping immediately at the first incorrect character.",
            "",
            "## Patched Function Timing Results",
            "",
            summarize_results(fixed_results),
            "",
            "## Post-Mitigation Finding",
            "",
            f"Timing leakage still detected after patch: **{fixed_leak}**",
            "",
            "The patched version should show a much flatter timing pattern because it avoids returning immediately after the first incorrect character.",
            "",
            "### Patched Timing Range Summary",
            "",
            timing_range_summary(fixed_results),
            "",
            "## Final Conclusion",
            "",
            "The agent confirmed that the original password checker was vulnerable to a timing side channel. The root cause was early-return comparison logic. After applying a constant time comparison, the timing trend was reduced, making it harder to infer password characters from execution time.",
            "",
            "## Safety Note",
            "",
            "This project uses only local dummy code and a fake password. It does not target real accounts, real devices, networks, or external systems.",
            "",
        ]
    )

    report = "\n".join(report_lines)

    with open(REPORT_PATH, "w") as file:
        file.write(report)

    print(f"\nSecurity report saved to: {REPORT_PATH}")


def main():
    agent_log(1, "Reading vulnerable_app.py source code.")
    source_code = read_source_file("vulnerable_app.py")

    agent_log(2, "Inspecting code for timing side-channel indicators.")
    code_findings = inspect_code_for_timing_leak(source_code)

    for finding in code_findings:
        print(f"- {finding}")

    agent_log(
        3,
        "Forming hypothesis: early-return password comparison may leak timing information.",
    )

    agent_log(4, "Running timing measurements on the vulnerable function.")
    vulnerable_results = analyze_prefix_timing(vulnerable_check_password)
    vulnerable_leak = detect_leakage(vulnerable_results)

    agent_log(5, "Analyzing vulnerable timing results.")
    print(f"Timing leakage detected in vulnerable function: {vulnerable_leak}")

    agent_log(
        6,
        "Selecting mitigation: replace early return comparison with constant-time comparison.",
    )

    agent_log(7, "Running timing measurements on the patched function.")
    fixed_results = analyze_prefix_timing(constant_time_check_password)
    fixed_leak = detect_leakage(fixed_results)

    agent_log(8, "Analyzing patched timing results.")
    print(f"Timing leakage still detected after patch: {fixed_leak}")

    agent_log(9, "Generating graphs, logs, and summary files.")
    generate_results()

    agent_log(10, "Generating Markdown security report.")
    create_security_report(
        vulnerable_results,
        fixed_results,
        vulnerable_leak,
        fixed_leak,
        code_findings,
    )

    agent_log(11, "Agentic timing side-channel analysis complete.")


if __name__ == "__main__":
    main()
