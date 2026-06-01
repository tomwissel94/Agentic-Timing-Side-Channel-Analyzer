import hmac


def patched_check_password(guess: str, secret: str = "UGoTtHE") -> bool:
    """
    Patched password comparison.

    This avoids the early-return behavior that causes timing leakage.
    """
    return hmac.compare_digest(guess, secret)


def explain_patch():
    explanation = """
The original password checker returned immediately when it found the first
incorrect character. This means guesses with more correct starting characters
took longer to reject, which creates a timing side channel.

The patched version uses hmac.compare_digest(), which is designed to compare
values without leaking useful information through early exit timing behavior.
"""
    return explanation


if __name__ == "__main__":
    print(explain_patch())

    test_guess = "UGoTtHE"
    print(f"Testing patched function with guess {test_guess}:")
    print(patched_check_password(test_guess))
