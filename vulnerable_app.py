import time
import hmac

SECRET_PASSWORD = "UGoTtHE"


def vulnerable_check_password(guess: str) -> bool:
    """
    Intentionally vulnerable password check.

    This leaks timing information because it returns immediately
    when a character does not match. It also sleeps after each
    correct character to make the timing leak easier to observe.
    """
    for i in range(len(SECRET_PASSWORD)):
        if i >= len(guess) or guess[i] != SECRET_PASSWORD[i]:
            return False

        # Artificial delay to make the timing side channel obvious
        time.sleep(0.001)

    return len(guess) == len(SECRET_PASSWORD)


def constant_time_check_password(guess: str) -> bool:
    """
    Safer password check using constant-time comparison.

    hmac.compare_digest avoids returning early based on the first
    mismatched character.
    """
    return hmac.compare_digest(guess, SECRET_PASSWORD)
