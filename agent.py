import os
from datetime import datetime

from vulnerable_app import vulnerable_check_password, constant_time_check_password
from timing_analyzer import analyze_prefix_timing, detect_leakage
from results_generator import main as generate_results


RESULTS_DIR = "results"
REPORT_PATH = os.path.join(RESULTS_DIR, "security_report.md")


def agent_log(step, message):
    print(f"\n[Agent Step {step}] {message}")


def read_source_file(filename):
    with open(filename, "r") as file:
        return file.read()


def inspect_code_for_timing_leak(source_code):
    findings = []

    if "return False" in source_code:
        findings.append(
            "The code contains early return behavior. "
            "This can create a timing side channel because incorrect guesses "
            "may return faster than partially correct guesses."
        )

    if "time.sleep" in source_code:
        findings.append(
            "The code contains an artificial delay. "
            "This makes the timing side channel easier to observe during testing."
        )

    if "compare_digest" in source_code:
        findings.append(
            "The code contains hmac.compare_digest, which is a safer constant-time comparison method."
        )

    return findings


def summarize_results(results):
    summary_lines = []

    for guess, avg_time in results:
        summary_lines.append(f"- Guess `{guess}` average time: {avg_time:.8f} seconds")

    return "\n".join(summary_lines)


def create_security_report(vulnerable_results, fixed_results, vulnerable_leak, fixed_leak, code_findings):
    os.makedirs(RESULTS_DIR, exist_ok=True)

    report = f"""# Agentic Timing Side Channel Security Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Project Overview

This project demonstrates an agentic AI-style workflow for detecting and mitigating a timing side-channel vulnerability in a password-checking function.

The agent inspects source code, forms a hypothesis, runs timing measurements, analyzes the results, recommends a mitigation, retests the patched version, and produces this report.

## Agent Workflow

1. Inspect the vulnerable password checking code.
2. Identify possible timing leak patterns.
3. Run timing measurements against the vulnerable function.
4. Analyze whether execution time increases as more prefix characters are correct.
5. Recommend a constant time comparison mitigation.
6. Retest the patched function.
7. Generate final findings and result artifacts.

## Source Code Inspection Findings

{chr(10).join(f"- {finding}" for finding in code_findings)}

## Vulnerable Function Timing Results

{summarize_results(vulnerable_results)}

## Vulnerability Finding

Timing leakage detected: **{vulnerable_leak}**

The vulnerable implementation leaks timing information because it returns as soon as it finds an incorrect character. This means guesses with more correct starting characters take longer to reject.

## Recommended Mitigation

Replace early-return password comparison logic with a constant-time comparison method such as:

```python
hmac.compare_digest(guess, SECRET_PASSWORD)
