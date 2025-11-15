# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/breaches/models.py
#
# OWASP Top 10 considerations:
#   - A01/A07 (Access Control & AuthN/Z):
#       Access to these models is enforced at the view / admin permission level.
#       This module does not perform any auth logic directly.
#   - A02/A05 (Security Misconfiguration / Data Integrity):
#       Fields are typed with reasonable max_length and defaults. No secrets or
#       config are stored here; this is pure data modeling.
#   - A03/A05/A06 (Injection / XSS / Insecure Design):
#       * description can contain HTML from HIBP; templates MUST NOT render it
#         with |safe unless it has been sanitized.
#       * raw and JSON fields hold parsed API data and are not executed.
#   - A06 (Sensitive Data Exposure / Privacy):
#       Email addresses and breach data are PII. Be careful with logging and
#       exports that use these models.
#   - A09 (Logging & Monitoring):
#       Any logging involving these models should avoid dumping full PII or raw
#       JSON where not necessary.

from __future__ import annotations

from django.db import models
from django.utils import timezone

from core.models import TimeStampedModel


# ---------------------------------------------------------------------------
# EmailIdentity
# ---------------------------------------------------------------------------
class EmailIdentity(TimeStampedModel):
    """
    Represents a single email address being monitored.

    Inherits from TimeStampedModel, which typically provides:
      - created_at
      - updated_at

    OWASP notes:
      - This is PII. Avoid logging full addresses unnecessarily.
      - Uniqueness on address prevents accidental duplication.
    """
    address = models.EmailField(unique=True)

    def __str__(self) -> str:
        """Return the email address for admin/debug display."""
        return self.address


# ---------------------------------------------------------------------------
# BreachHit
# ---------------------------------------------------------------------------
class BreachHit(TimeStampedModel):
    """
    A normalized record of a single breach affecting an EmailIdentity.

    Most fields map directly from the HIBP breach schema. We deliberately
    store normalized types (dates, booleans, lists) for safer use in views
    and templates.

    OWASP notes:
      - description may contain HTML from HIBP. Templates should NOT pipe this
        through |safe without sanitization to avoid XSS.
      - This model contains sensitive breach metadata. Be cautious with logging
        and exports.
    """
    identity = models.ForeignKey(
        EmailIdentity,
        on_delete=models.CASCADE,
        related_name="hits",
    )

    # Core identity of the breach
    breach_name = models.CharField(  # HIBP "Name"
        max_length=200,
    )
    domain = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )
    occurred_on = models.DateField(  # HIBP "BreachDate"
        null=True,
        blank=True,
    )

    # Full model fields
    title = models.CharField(                # HIBP "Title"
        max_length=255,
        blank=True,
        default="",
    )
    # HIBP "Description" (often HTML). Treat as untrusted in templates.
    description = models.TextField(
        blank=True,
        default="",
    )
    # HIBP "PwnCount"
    pwn_count = models.BigIntegerField(
        null=True,
        blank=True,
    )
    # HIBP "DataClasses" -> list[str], stored as JSON.
    data_classes = models.JSONField(
        default=list,
        blank=True,
    )

    # Flags (never nullable; default False)
    is_verified = models.BooleanField(default=False)
    is_sensitive = models.BooleanField(default=False)
    is_fabricated = models.BooleanField(default=False)
    is_spam_list = models.BooleanField(default=False)
    is_retired = models.BooleanField(default=False)
    is_malware = models.BooleanField(default=False)
    is_stealer_log = models.BooleanField(default=False)
    is_subscription_free = models.BooleanField(default=False)

    # Additional timeline metadata
    added_on = models.DateField(  # HIBP "AddedDate"
        null=True,
        blank=True,
    )
    modified_on = models.DateField(  # HIBP "ModifiedDate"
        null=True,
        blank=True,
    )
    # HIBP "LogoPath" (filename), used to build a public logo URL.
    logo_path = models.CharField(
        max_length=500,
        blank=True,
        default="",
    )

    class Meta:
        """
        Model options:
          - unique_together: prevent duplicate breach records for the same
            identity + breach_name.
          - indexes: speed up common lookups by breach_name and identity/breach.
          - ordering: newest/most recent breaches first.
        """
        unique_together = ("identity", "breach_name")
        indexes = [
            models.Index(fields=["breach_name"]),
            models.Index(fields=["identity", "breach_name"]),
        ]
        ordering = ["-occurred_on", "-added_on", "-id"]

    def __str__(self) -> str:
        """Readable label combining identity and breach name."""
        return f"{self.identity.address} -> {self.breach_name}"

    @property
    def logo_url(self) -> str:
        """
        Build a public logo URL from the stored logo_path.

        OWASP notes:
          - This is a convenience accessor; it does not fetch or validate
            remote content.
          - The value is based entirely on HIBP data; do not treat it as
            executable or trusted input.
        """
        if not self.logo_path:
            return ""
        return (
            "https://haveibeenpwned.com/Content/Images/PwnedLogos/"
            f"{self.logo_path}"
        )


# ---------------------------------------------------------------------------
# ShodanFinding
# ---------------------------------------------------------------------------
class ShodanFinding(models.Model):
    """
    Normalized representation of a Shodan-style host result.

    Fields:
      - ip: IP address of the host.
      - hostnames: list of associated hostnames.
      - ports: list of open ports.
      - org: organization / ASN owner.
      - os: detected operating system (if any).
      - raw: full JSON document from the Shodan API.
      - created_on / last_seen: timestamps for ingest and last observation.

    OWASP notes:
      - raw is parsed JSON and should never be executed.
      - IP + hostnames can be considered sensitive in some contexts; avoid
        logging raw data unless needed.
    """
    ip = models.GenericIPAddressField()
    hostnames = models.JSONField(
        default=list,
        blank=True,
    )  # list[str]
    ports = models.JSONField(
        default=list,
        blank=True,
    )  # list[int]
    org = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )
    os = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )
    raw = models.JSONField(
        default=dict,
        blank=True,
    )  # full Shodan host JSON
    created_on = models.DateTimeField(
        auto_now_add=True,
    )
    last_seen = models.DateTimeField(
        default=timezone.now,
    )

    class Meta:
        """
        Default ordering: newest/most recently seen hosts first.
        """
        ordering = ["-last_seen", "-id"]

    def __str__(self) -> str:
        """
        Show IP and hostnames for admin/debug display.

        Uses ', '.join(...) on hostnames; if empty, shows just IP.
        """
        host_display = ", ".join(self.hostnames or [])
        return f"{self.ip} ({host_display})"
