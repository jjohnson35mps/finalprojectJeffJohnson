# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# Django admin configuration for the breaches app.
#
# OWASP-relevant notes:
#   - A01/A07 (Access control): Django admin is already restricted to staff users
#     with proper permissions; ensure you’re using strong auth + HTTPS in settings.
#   - A05 (Security misconfiguration) / A06 (Data integrity):
#       * We expose only non-sensitive fields (email, breach meta, Shodan meta).
#       * Timestamp fields are marked read-only so they can’t be silently altered
#         via the admin UI.
#   - A09 (Logging & monitoring): Any security-sensitive logging should live in
#     models/views, not here.

from django.contrib import admin
from .models import EmailIdentity, BreachHit, ShodanFinding


@admin.register(EmailIdentity)
class EmailIdentityAdmin(admin.ModelAdmin):
    """
    Admin configuration for tracked email identities.

    - list_display: which fields show up in the change list.
    - search_fields: allow quick lookup by email address.
    - ordering: newest identities first.
    - readonly_fields: created_at is system-managed; don’t allow edits from admin.
    """
    list_display = ("address", "created_at")
    search_fields = ("address",)
    ordering = ("-created_at",)
    readonly_fields = ("created_at",)


@admin.register(BreachHit)
class BreachHitAdmin(admin.ModelAdmin):
    """
    Admin configuration for normalized breach results.

    - list_display: key breach metadata per row.
    - list_filter: quick filters for date and important flags (verified/sensitive/malware).
    - search_fields: search across breach name, domain, and linked identity address.
    - ordering: show most recent breaches first.
    - readonly_fields: timestamps are managed by ingestion logic, not edited by admins.
    """
    list_display = ("identity", "breach_name", "domain", "occurred_on", "pwn_count")
    list_filter = ("occurred_on", "is_verified", "is_sensitive", "is_malware")
    search_fields = ("breach_name", "domain", "identity__address")
    ordering = ("-occurred_on", "-added_on")
    readonly_fields = ("added_on", "modified_on")


@admin.register(ShodanFinding)
class ShodanFindingAdmin(admin.ModelAdmin):
    """
    Admin configuration for Shodan-style host findings.

    - list_display: high-level host summary.
    - search_fields: search by IP, org, or OS.
    - list_filter: common pivots for quick filtering.
    - ordering: most recently seen hosts first.
    - readonly_fields: last_seen is set by the scanner pipeline.
    """
    list_display = ("ip", "org", "os", "last_seen")
    search_fields = ("ip", "org", "os")
    list_filter = ("org", "os")
    ordering = ("-last_seen",)
    readonly_fields = ("last_seen",)
