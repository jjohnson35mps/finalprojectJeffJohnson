# src/breaches/models.py
# ----------------------
# Core data models for Dark Web Leak Finder.
# EmailIdentity stores a unique email address to monitor.
# BreachHit stores a (identity, breach) association with optional domain/date.
from django.db import models
from core.models import TimeStampedModel

class EmailIdentity(TimeStampedModel):
    address = models.EmailField(unique=True)

    def __str__(self) -> str:
        return self.address

class BreachHit(TimeStampedModel):
    identity = models.ForeignKey(
        EmailIdentity, on_delete=models.CASCADE, related_name="hits"
    )
    breach_name = models.CharField(max_length=200)
    domain = models.CharField(max_length=200, blank=True)
    occurred_on = models.DateField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["breach_name"]),
            models.Index(fields=["identity", "breach_name"]),
        ]

    def __str__(self) -> str:
        return f"{self.identity.address} -> {self.breach_name}"
