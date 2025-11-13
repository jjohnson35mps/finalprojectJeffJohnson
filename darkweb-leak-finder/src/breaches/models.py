# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/breaches/models.py

from __future__ import annotations

from django.db import models
from django.utils import timezone
from core.models import TimeStampedModel


class EmailIdentity(TimeStampedModel):
    address = models.EmailField(unique=True)

    def __str__(self) -> str:
        return self.address


class BreachHit(TimeStampedModel):
    identity = models.ForeignKey(
        EmailIdentity, on_delete=models.CASCADE, related_name="hits"
    )

    # Core identity of the breach
    breach_name = models.CharField(max_length=200)                 # HIBP "Name"
    domain = models.CharField(max_length=255, blank=True, default="")
    occurred_on = models.DateField(null=True, blank=True)          # HIBP "BreachDate"

    # Full model fields
    title = models.CharField(max_length=255, blank=True, default="")           # "Title"
    description = models.TextField(blank=True, default="")                     # "Description" (HTML)
    pwn_count = models.BigIntegerField(null=True, blank=True)                  # "PwnCount"
    data_classes = models.JSONField(default=list, blank=True)                  # "DataClasses" -> list[str]

    # Flags (never nullable; default False)
    is_verified = models.BooleanField(default=False)
    is_sensitive = models.BooleanField(default=False)
    is_fabricated = models.BooleanField(default=False)
    is_spam_list = models.BooleanField(default=False)
    is_retired = models.BooleanField(default=False)
    is_malware = models.BooleanField(default=False)
    is_stealer_log = models.BooleanField(default=False)
    is_subscription_free = models.BooleanField(default=False)

    added_on = models.DateField(null=True, blank=True)             # "AddedDate"
    modified_on = models.DateField(null=True, blank=True)          # "ModifiedDate"
    logo_path = models.CharField(max_length=500, blank=True, default="")       # "LogoPath" (filename)

    class Meta:
        unique_together = ("identity", "breach_name")
        indexes = [
            models.Index(fields=["breach_name"]),
            models.Index(fields=["identity", "breach_name"]),
        ]
        ordering = ["-occurred_on", "-added_on", "-id"]

    def __str__(self) -> str:
        return f"{self.identity.address} -> {self.breach_name}"

    @property
    def logo_url(self) -> str:
        """Public logo URL (HIBP hosts images under this path)."""
        if not self.logo_path:
            return ""
        return f"https://haveibeenpwned.com/Content/Images/PwnedLogos/{self.logo_path}"


class ShodanFinding(models.Model):
    """Normalized Shodan host result"""
    ip = models.GenericIPAddressField()
    hostnames = models.JSONField(default=list, blank=True)   # list[str]
    ports = models.JSONField(default=list, blank=True)       # list[int]
    org = models.CharField(max_length=255, blank=True, default="")
    os = models.CharField(max_length=255, blank=True, default="")
    raw = models.JSONField(default=dict, blank=True)         # full Shodan host JSON
    created_on = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-last_seen", "-id"]

    def __str__(self):
        return f"{self.ip} ({', '.join(self.hostnames or [])})"
