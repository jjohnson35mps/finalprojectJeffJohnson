# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project

from django.contrib import admin
from .models import EmailIdentity, BreachHit, ShodanFinding

@admin.register(EmailIdentity)
class EmailIdentityAdmin(admin.ModelAdmin):
    list_display = ("address", "created_at")
    search_fields = ("address",)
    ordering = ("-created_at",)

@admin.register(BreachHit)
class BreachHitAdmin(admin.ModelAdmin):
    list_display = ("identity", "breach_name", "domain", "occurred_on", "pwn_count")
    list_filter = ("occurred_on", "is_verified", "is_sensitive", "is_malware")
    search_fields = ("breach_name", "domain", "identity__address")
    ordering = ("-occurred_on", "-added_on")

@admin.register(ShodanFinding)
class ShodanFindingAdmin(admin.ModelAdmin):
    list_display = ("ip", "org", "os", "last_seen")
    search_fields = ("ip", "org", "os")
    list_filter = ("org", "os")
    ordering = ("-last_seen",)
