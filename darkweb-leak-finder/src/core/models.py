# src/core/models.py
# ------------------
# Reusable abstract base with created_at / updated_at timestamps.
# Other apps can "from core.models import TimeStampedModel" and subclass it.
from django.db import models

class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
