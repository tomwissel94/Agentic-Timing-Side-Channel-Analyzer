# Agentic Timing Side Channel Security Report

Generated: 2026-06-01 14:27:32

## Project Overview

This project demonstrates an agentic AI style workflow for detecting and mitigating a timing side-channel vulnerability in a password-checking function.

The agent inspects source code, forms a hypothesis, runs timing measurements, analyzes the results, recommends a mitigation, retests the patched version, and produces this report.

## Agent Workflow

1. Inspect the vulnerable password-checking code.
2. Identify possible timing leak patterns.
3. Run timing measurements against the vulnerable function.
4. Analyze whether execution time increases as more prefix characters are correct.
5. Recommend a constant-time comparison mitigation.
6. Retest the patched function.
7. Generate final findings and result artifacts.

## Source Code Inspection Findings

- Early-return behavior was found. This can create a timing side channel because incorrect guesses may return faster than partially correct guesses.
- An artificial delay was found. This makes the timing side channel easier to observe during testing.
- A constant-time comparison method, hmac.compare_digest, was found. This is an appropriate mitigation for timing leakage in string comparison.

## Vulnerable Function Timing Results

- Guess `XXXXXXX` average time: `0.00000027` seconds
- Guess `UXXXXXX` average time: `0.00125695` seconds
- Guess `UGXXXXX` average time: `0.00251701` seconds
- Guess `UGoXXXX` average time: `0.00377483` seconds
- Guess `UGoTXXX` average time: `0.00504704` seconds
- Guess `UGoTtXX` average time: `0.00631646` seconds
- Guess `UGoTtHX` average time: `0.00756909` seconds
- Guess `UGoTtHE` average time: `0.00885028` seconds

## Vulnerability Finding

Timing leakage detected: **True**

The vulnerable implementation leaks timing information because it returns as soon as it finds an incorrect character. This means guesses with more correct starting characters take longer to reject.

### Vulnerable Timing Range Summary

First guess `XXXXXXX`: `0.00000027` seconds

Last guess `UGoTtHE`: `0.00885028` seconds

Difference: `0.00885001` seconds

## Recommended Mitigation

Replace early-return password comparison logic with a constant-time comparison method such as:

```python
hmac.compare_digest(guess, SECRET_PASSWORD)
```

This reduces timing leakage because the comparison avoids stopping immediately at the first incorrect character.

## Patched Function Timing Results

- Guess `XXXXXXX` average time: `0.00000123` seconds
- Guess `UXXXXXX` average time: `0.00000060` seconds
- Guess `UGXXXXX` average time: `0.00000054` seconds
- Guess `UGoXXXX` average time: `0.00000078` seconds
- Guess `UGoTXXX` average time: `0.00000031` seconds
- Guess `UGoTtXX` average time: `0.00000031` seconds
- Guess `UGoTtHX` average time: `0.00000030` seconds
- Guess `UGoTtHE` average time: `0.00000029` seconds

## Post-Mitigation Finding

Timing leakage still detected after patch: **False**

The patched version should show a much flatter timing pattern because it avoids returning immediately after the first incorrect character.

### Patched Timing Range Summary

First guess `XXXXXXX`: `0.00000123` seconds

Last guess `UGoTtHE`: `0.00000029` seconds

Difference: `-0.00000094` seconds

## Final Conclusion

The agent confirmed that the original password checker was vulnerable to a timing side channel. The root cause was early-return comparison logic. After applying a constant time comparison, the timing trend was reduced, making it harder to infer password characters from execution time.

## Safety Note

This project uses only local dummy code and a fake password. It does not target real accounts, real devices, networks, or external systems.
