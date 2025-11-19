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

    # created_at:
    #   - Timestamp of when the record was first created in the database.
    #   - auto_now_add=True means Django sets it once on initial save and
    #     never changes it afterward.
    created_at = models.DateTimeField(auto_now_add=True)

    # updated_at:
    #   - Timestamp of the last time the record was saved.
    #   - auto_now=True means Django updates this field automatically on
    #     each call to .save(), giving you a simple "last modified" time.
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # abstract:
        #   - Marks this model as an abstract base class.
        #   - Django will NOT create a separate database table for
        #     TimeStampedModel itself; instead, its fields are copied
        #     into each concrete subclass that inherits from it.
        abstract = True
