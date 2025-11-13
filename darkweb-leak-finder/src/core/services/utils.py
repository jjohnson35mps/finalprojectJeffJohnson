# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# Reusable utilities (validators, parsing helpers, etc.)
import re

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def is_valid_email(value: str) -> bool:
    return bool(EMAIL_REGEX.match(value or ""))
