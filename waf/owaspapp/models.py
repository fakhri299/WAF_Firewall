# models.py
from django.db import models
import uuid

class AttackType(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, blank=True, null=True)
    ip = models.GenericIPAddressField(null=True)
    port = models.PositiveIntegerField(null=True)
    detect_time = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return self.ip

