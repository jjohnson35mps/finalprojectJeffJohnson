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
    # address:
    #   - Primary key-like field for the identity (unique email address).
    #   - Used to link all associated breach hits.
    address = models.EmailField(unique=True)

    def __str__(self) -> str:
        """
        Return the email address for admin/debug display.

        Used by Django admin, shell, and templates when an EmailIdentity
        instance is coerced to string.
        """
        return str(self.address)


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
    # identity:
    #   - Foreign key to the monitored email address.
    #   - CASCADE ensures all related breaches are removed if the identity
    #     itself is deleted.
    identity = models.ForeignKey(
        EmailIdentity,
        on_delete=models.CASCADE,
        related_name="hits",
    )

    # Core identity of the breach
    # breach_name:
    #   - Internal/HIBP name for the breach (e.g., "Adobe").
    #   - Used to de-duplicate records per identity.
    breach_name = models.CharField(  # HIBP "Name"
        max_length=200,
    )

    # domain:
    #   - Domain associated with the breach (e.g., "adobe.com").
    #   - Optional; defaults to an empty string when not provided.
    domain = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )

    # occurred_on:
    #   - Date the breach occurred, if known.
    #   - Nullable because some breaches do not have a precise date.
    occurred_on = models.DateField(  # HIBP "BreachDate"
        null=True,
        blank=True,
    )

    # Full model fields

    # title:
    #   - Human-readable title for the breach (HIBP "Title").
    #   - Shown to users instead of the internal breach_name.
    title = models.CharField(                # HIBP "Title"
        max_length=255,
        blank=True,
        default="",
    )

    # description:
    #   - Long-form description of the incident.
    #   - Often contains HTML from HIBP; treat as untrusted in templates.
    #   - Do not mark safe unless sanitized.
    # HIBP "Description" (often HTML). Treat as untrusted in templates.
    description = models.TextField(
        blank=True,
        default="",
    )

    # pwn_count:
    #   - Number of affected accounts in the breach (HIBP "PwnCount").
    #   - Nullable; may not be present for every record.
    # HIBP "PwnCount"
    pwn_count = models.BigIntegerField(
        null=True,
        blank=True,
    )

    # data_classes:
    #   - Categories of leaked data (e.g., "Email addresses", "Passwords").
    #   - Stored as a JSON list of strings for easy filtering/analysis.
    # HIBP "DataClasses" -> list[str], stored as JSON.
    data_classes = models.JSONField(
        default=list,
        blank=True,
    )

    # Flags (never nullable; default False)
    # is_verified:
    #   - Indicates whether HIBP considers the breach verified/legitimate.
    is_verified = models.BooleanField(default=False)

    # is_sensitive:
    #   - True for highly sensitive breaches, which may be hidden or treated
    #     more carefully in the UI.
    is_sensitive = models.BooleanField(default=False)

    # is_fabricated:
    #   - Marks breaches believed to be fabricated.
    #   - Useful to down-rank or filter in user-facing views.
    is_fabricated = models.BooleanField(default=False)

    # is_spam_list:
    #   - True when the breach is actually a spam list, not a traditional
    #     site compromise.
    is_spam_list = models.BooleanField(default=False)

    # is_retired:
    #   - Indicates the breach has been retired / no longer actively listed.
    is_retired = models.BooleanField(default=False)

    # is_malware:
    #   - True when the data comes from malware activity (e.g., keyloggers).
    is_malware = models.BooleanField(default=False)

    # is_stealer_log:
    #   - True when the breach originates from stealer logs (e.g., infostealers
    #     capturing browser-stored credentials).
    is_stealer_log = models.BooleanField(default=False)

    # is_subscription_free:
    #   - Indicates whether the breach is visible without a paid HIBP
    #     subscription.
    is_subscription_free = models.BooleanField(default=False)

    # Additional timeline metadata

    # added_on:
    #   - Date the breach was added to HIBP.
    #   - Can differ from the actual breach date.
    added_on = models.DateField(  # HIBP "AddedDate"
        null=True,
        blank=True,
    )

    # modified_on:
    #   - Date HIBP last updated the breach metadata.
    modified_on = models.DateField(  # HIBP "ModifiedDate"
        null=True,
        blank=True,
    )

    # logo_path:
    #   - HIBP logo filename, used to construct a full logo URL.
    #   - Stored as a relative path, not a full URL.
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
        # unique_together:
        #   - Ensures a given email identity can only have one record per
        #     breach_name, preventing duplicate entries.
        unique_together = ("identity", "breach_name")

        # indexes:
        #   - Index on breach_name: speeds up queries filtering by breach.
        #   - Index on (identity, breach_name): optimizes lookups for a specific
        #     breach per user identity.
        indexes = [
            models.Index(fields=["breach_name"]),
            models.Index(fields=["identity", "breach_name"]),
        ]

        # ordering:
        #   - Default sort order: most recent breach date first, then by
        #     added date, then by id as a tie breaker.
        ordering = ["-occurred_on", "-added_on", "-id"]

    def __str__(self) -> str:
        """
        Readable label combining identity and breach name.

        Useful in the admin and shell for quick identification of which
        email was affected by which breach.
        """
        return f"{str(self.identity)} -> {self.breach_name}"

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
    # ip:
    #   - IP address of the discovered host (IPv4/IPv6).
    #   - Primary lookup key when correlating with other systems.
    ip = models.GenericIPAddressField()

    # hostnames:
    #   - JSON list of hostnames associated with the IP.
    #   - Usually values from reverse DNS or banners (e.g., ["example.com"]).
    hostnames = models.JSONField(
        default=list,
        blank=True,
    )  # list[str]

    # ports:
    #   - JSON list of open ports observed by Shodan.
    #   - Used to see which services are exposed on the host.
    ports = models.JSONField(
        default=list,
        blank=True,
    )  # list[int]

    # org:
    #   - Organization/owner associated with the IP address (e.g., ISP or ASN).
    org = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )

    # os:
    #   - Detected operating system, if Shodan could infer one.
    #   - Often blank when OS detection is not possible.
    os = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )

    # raw:
    #   - Full Shodan JSON payload for the host.
    #   - Provides access to additional fields not normalized into columns.
    raw = models.JSONField(
        default=dict,
        blank=True,
    )  # full Shodan host JSON

    # created_on:
    #   - Timestamp when this record was first inserted.
    #   - Set automatically at creation time.
    created_on = models.DateTimeField(
        auto_now_add=True,
    )

    # last_seen:
    #   - Timestamp when this host was last observed/refreshed.
    #   - Updated by application code whenever a new observation for this host
    #     is ingested.
    last_seen = models.DateTimeField(
        default=timezone.now,
    )

    class Meta:
        """
        Default ordering: newest/most recently seen hosts first.
        """
        # ordering:
        #   - Sorts by last_seen descending, then id descending.
        #   - Ensures the most recently observed hosts appear first in queries.
        ordering = ["-last_seen", "-id"]

    def __str__(self) -> str:
        """
        Show IP and hostnames for admin/debug display.

        Uses ', '.join(...) on hostnames; if empty, shows just IP.
        """
        host_display = ", ".join(self.hostnames or [])
        return f"{self.ip} ({host_display})"
