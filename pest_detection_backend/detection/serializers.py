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
    serverid = serializers.UUIDField(source='server_id', required=True)  # 👈 this is perfect

    class Meta:
        model = DetectionResult
        fields = ['serverid',  'updated_at1', 'image', 'timestamp', 'detection_date', 'note', 'bounding_boxes']

    def create(self, validated_data):
        bounding_boxes_data = validated_data.pop('bounding_boxes')
        server_id = validated_data.pop('server_id')

        detection = DetectionResult.objects.create(
            user=self.context['user'],
            server_id=server_id,
            **validated_data
        )

        for box_data in bounding_boxes_data:
            BoundingBox.objects.create(detection=detection, **box_data)

        return detection


class DetectionBatchSerializer(serializers.Serializer):
    detections = DetectionItemWriteSerializer(many=True)

    def create(self, validated_data):
        # validated_data['detections'] is already a list of validated dicts
        return [self.fields['detections'].child.create(item) for item in validated_data['detections']]
