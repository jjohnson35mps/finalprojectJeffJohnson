# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/core/models.py
#
# Shared abstract models for the project.
#
# OWASP Top 10 touchpoints:
#   - A09: Security Logging & Monitoring Failures
#       * Centralized created_at / updated_at fields make it easier to
#         audit when security-relevant records (e.g., breach hits,
#         scan results, identities) were created or modified.
#       * This class does not itself log who changed a record; if you
#         need full audit trails, combine this with request-based
#         logging or an auditing app.
#   - A02: Security Misconfiguration
#       * No secrets or environment-specific configuration is stored here.
#       * Logic is limited to safe, generic timestamping behavior.

from django.db import models


class TimeStampedModel(models.Model):
    """
    Abstract base model that adds created/updated timestamps.

    Fields:
        created_at:
            - DateTime (auto_now_add=True)
            - Set once when the object is first created.
        updated_at:
            - DateTime (auto_now=True)
            - Updated automatically on each save().

    Usage:
        - Inherit from TimeStampedModel in other apps (e.g., breaches,
          security_ticker) to add these fields without repeating code:

              class EmailIdentity(TimeStampedModel):
                  address = models.EmailField(unique=True)

        - Because this is abstract, no DB table is created for it alone.
    """

    # When the record is created (immutable once set).
    created_at = models.DateTimeField(auto_now_add=True)

    # Updated automatically every time the record is saved.
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # Mark this as an abstract base class so Django does not create
        # a separate table for TimeStampedModel.
        abstract = True
