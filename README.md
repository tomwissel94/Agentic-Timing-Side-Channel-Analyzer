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

```bash
python3 agent_controller.py
