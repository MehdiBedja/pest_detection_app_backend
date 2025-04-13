import uuid
import os
from django.db import models
from django.conf import settings


def detection_image_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"{instance.server_id}.{ext}"
    return os.path.join('static/images/', filename)


class DetectionResult(models.Model):
    server_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='detections'
    )

    image = models.ImageField(
        upload_to=detection_image_upload_path,
        null=True,
        blank=True
    )

    timestamp = models.BigIntegerField()
    detection_date = models.BigIntegerField()
    note = models.TextField(null=True, blank=True)

    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Detection {self.server_id} by {self.user}"

    @property
    def image_url(self):
        if self.image:
            return f"/{self.image.url}"
        return None



class BoundingBox(models.Model):
    detection = models.ForeignKey(
        DetectionResult,
        on_delete=models.CASCADE,
        related_name='bounding_boxes'
    )

    x1 = models.FloatField()
    y1 = models.FloatField()
    x2 = models.FloatField()
    y2 = models.FloatField()
    cx = models.FloatField()
    cy = models.FloatField()
    w = models.FloatField()
    h = models.FloatField()
    cnf = models.FloatField()
    cls = models.IntegerField()
    cls_name = models.CharField(max_length=100)

    def __str__(self):
        return f"Box {self.cls_name} for detection {self.detection.server_id}"
