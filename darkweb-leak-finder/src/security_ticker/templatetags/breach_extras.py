# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# breaches/templatetags/breach_extras.py

from django import template
import json

register = template.Library()

@register.filter
def to_list(value):
    """Coerce various input shapes to a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        # Try JSON first
        try:
            parsed = json.loads(value)
            if isinstance(parsed, (list, tuple)):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            pass
        # Fallback: CSV
        return [s.strip() for s in value.split(",") if s.strip()]
    # Last resort: stringify then split on commas
    return [s.strip() for s in str(value).split(",") if s.strip()]
