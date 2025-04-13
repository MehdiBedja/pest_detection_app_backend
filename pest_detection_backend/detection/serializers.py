# serializers.py
from rest_framework import serializers
from .models import DetectionResult, BoundingBox

class BoundingBoxReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = BoundingBox
        fields = '__all__'

class DetectionResultReadSerializer(serializers.ModelSerializer):
    bounding_boxes = BoundingBoxReadSerializer(many=True, read_only=True)

    image_url = serializers.SerializerMethodField()

    class Meta:
        model = DetectionResult
        fields = '__all__'  # this should include `bounding_boxes`

    def get_image_url(self, obj):
        if obj.image and hasattr(obj.image, 'url'):
            return obj.image.url
        return None





class BoundingBoxWriteSerializer(serializers.ModelSerializer):
    class Meta:
        model = BoundingBox
        exclude = ['detection']


class DetectionItemWriteSerializer(serializers.ModelSerializer):
    bounding_boxes = BoundingBoxWriteSerializer(many=True)

    class Meta:
        model = DetectionResult
        fields = ['image', 'timestamp', 'detection_date', 'note', 'bounding_boxes']

    def create(self, validated_data):
        bounding_boxes_data = validated_data.pop('bounding_boxes')
        detection = DetectionResult.objects.create(user=self.context['user'], **validated_data)
        for box_data in bounding_boxes_data:
            BoundingBox.objects.create(detection=detection, **box_data)
        return detection


class DetectionBatchSerializer(serializers.Serializer):
    detections = DetectionItemWriteSerializer(many=True)

    def create(self, validated_data):
        return [self.fields['detections'].child.create(item) for item in validated_data['detections']]
