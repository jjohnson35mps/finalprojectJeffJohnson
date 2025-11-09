# security_ticker/templatetags/security_ticker_tags.py
from django import template

register = template.Library()

@register.inclusion_tag("security_ticker/_ticker.html", takes_context=True)
def security_ticker(context):
    """
    Renders the ticker container. JS will fetch the feed.
    """
    return {}
