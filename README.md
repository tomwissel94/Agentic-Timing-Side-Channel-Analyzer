# Agentic Timing Side Channel Analyzer
Final Project for ECE 202C - IOT Security

## Overview

This project demonstrates an agentic AI-style workflow for detecting and mitigating a timing side-channel vulnerability in a password-checking function.

The system tests whether a password checker leaks information through runtime differences. It then applies a safer constant-time comparison and retests the system to show that the timing leak is reduced.

## Course Connection

This project connects to ECE 202C topics including:

- Side-channel attacks
- Software security
- Timing leakage
- Secure coding
- Agentic AI for security analysis

## Files

- `vulnerable_app.py`  
  Contains an intentionally vulnerable password checker and a safer constant-time checker.

- `timing_analyzer.py`  
  Measures execution time for different password guesses and checks whether timing increases with correct prefix length.

- `constant_time_patch.py`  
  Explains and implements the constant-time mitigation.

- `agent_controller.py`  
  Runs the full agentic workflow: inspect, test, analyze, patch, retest, and summarize.

- `results/`  
  Folder for storing screenshots, logs, or output files.

## How to Run

Install the required Python package:

```bash
pip3 install matplotlib
```

Run the full agentic workflow:

```bash
python3 agent.py
```

This will:

1. Inspect the vulnerable password-checking code.
2. Run timing measurements on the vulnerable function.
3. Detect timing leakage.
4. Recommend a constant-time comparison mitigation.
5. Retest the patched function.
6. Generate result artifacts in the `results/` folder.

After running the agent, the `results/` folder should contain:

```text
results/
├── vulnerable_timing.png
├── fixed_timing.png
├── run_log.txt
├── summary.txt
└── security_report.md
```

You can also run the timing analyzer directly:

```bash
python3 timing_analyzer.py
```

Or generate only the result graphs and logs:

```bash
python3 results_generator.py
```

## Expected Output

The vulnerable password checker should show increasing execution time as more characters of the password guess are correct.

The patched version should show a flatter timing pattern because it uses `hmac.compare_digest()` instead of returning immediately after the first incorrect character.

## Agentic Workflow Explanation

This project is designed to model an agentic security workflow. The agent does not simply run one script. Instead, it performs a sequence of security-analysis steps:

1. Reads the target source code.
2. Identifies timing side-channel indicators.
3. Forms a hypothesis about the vulnerability.
4. Runs timing experiments.
5. Interprets the timing results.
6. Selects a mitigation.
7. Retests the patched implementation.
8. Generates graphs, logs, summaries, and a security report.

This matches the agentic AI idea because the workflow combines code inspection, tool execution, result analysis, mitigation selection, and final reporting.

## Safety and Ethics

This project uses only local demonstration code and a fake password. It does not target real systems, accounts, networks, or devices.
