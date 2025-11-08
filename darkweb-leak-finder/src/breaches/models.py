# src/breaches/models.py
# ----------------------
# Core data models for Dark Web Leak Finder.
# EmailIdentity stores a unique email address to monitor.
# BreachHit stores a (identity, breach) association with optional domain/date.
# src/breaches/models.py
# ------------------------------------------------------------
# Stores the complete HIBP breach model including IsStealerLog and
# IsSubscriptionFree. Adds a convenience property for the absolute logo URL.

from __future__ import annotations
from django.db import models
from core.models import TimeStampedModel

class EmailIdentity(TimeStampedModel):
    address = models.EmailField(unique=True)
    def __str__(self) -> str:  # trivial
        return self.address

class BreachHit(TimeStampedModel):
    identity = models.ForeignKey(
        EmailIdentity, on_delete=models.CASCADE, related_name="hits"
    )

    # Core identity of the breach
    breach_name = models.CharField(max_length=200)             # "Name"
    domain = models.CharField(max_length=255, blank=True)      # "Domain"
    occurred_on = models.DateField(null=True, blank=True)      # "BreachDate"

    # Full model fields
    title = models.CharField(max_length=255, blank=True)       # "Title"
    description = models.TextField(blank=True)                 # "Description" (HTML)
    pwn_count = models.IntegerField(null=True, blank=True)     # "PwnCount"
    data_classes = models.JSONField(null=True, blank=True)     # "DataClasses"

    is_verified = models.BooleanField(null=True, blank=True)       # "IsVerified"
    is_sensitive = models.BooleanField(null=True, blank=True)      # "IsSensitive"
    is_fabricated = models.BooleanField(null=True, blank=True)     # "IsFabricated"
    is_spam_list = models.BooleanField(null=True, blank=True)      # "IsSpamList"
    is_retired = models.BooleanField(null=True, blank=True)        # "IsRetired"
    is_malware = models.BooleanField(null=True, blank=True)        # "IsMalware"
    is_stealer_log = models.BooleanField(null=True, blank=True)    # "IsStealerLog"
    is_subscription_free = models.BooleanField(null=True, blank=True)  # "IsSubscriptionFree"

    added_on = models.DateField(null=True, blank=True)         # "AddedDate"
    modified_on = models.DateField(null=True, blank=True)      # "ModifiedDate"
    logo_path = models.CharField(max_length=500, blank=True)   # "LogoPath" (filename)

    class Meta:
        unique_together = ("identity", "breach_name")
        indexes = [
            models.Index(fields=["breach_name"]),
            models.Index(fields=["identity", "breach_name"]),
        ]

    def __str__(self) -> str:  # trivial
        return f"{self.identity.address} -> {self.breach_name}"

    @property
    def logo_url(self) -> str:
        """
        Build the public logo URL. HIBP typically returns only a filename
        like 'Adobe.png', which lives under the Content/Images/PwnedLogos path.
        """
        if not self.logo_path:
            return ""
        # Works whether .png/.svg; HIBP hosts both under this base.
        return f"https://haveibeenpwned.com/Content/Images/PwnedLogos/{self.logo_path}"
