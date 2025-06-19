from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
from .serializers import *
from .models import *
from rest_framework.decorators import parser_classes
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser


from uuid import UUID

from uuid import UUID

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from uuid import UUID
from .models import DetectionResult



import cloudinary

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def debug_cloudinary(request):
    """Debug endpoint to check Cloudinary configuration"""
    
    debug_info = {
        'DEBUG': settings.DEBUG,
        'DEFAULT_FILE_STORAGE': getattr(settings, 'DEFAULT_FILE_STORAGE', 'Not set'),
        'CLOUDINARY_STORAGE': settings.CLOUDINARY_STORAGE,
        'CLOUDINARY_CONFIG': {
            'cloud_name': cloudinary.config().cloud_name,
            'api_key': cloudinary.config().api_key,
            'api_secret': 'SET' if cloudinary.config().api_secret else 'NOT SET',
        }
    }
    
    logger.info(f"Cloudinary Debug Info: {debug_info}")
    return Response(debug_info, status=200)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def get_detections_by_ids(request):
    user = request.user

    # 1. Extract client-side IDs
    if request.method == 'GET':
        ids = request.query_params.get('ids')
        if not ids:
            return Response({"error": "Missing 'ids' parameter in query"}, status=400)
        try:
            client_ids = [UUID(i.strip()) for i in ids.split(',')]
        except ValueError:
            return Response({"error": "Invalid UUID format in query string"}, status=400)
    else:  # POST with JSON
        client_ids = request.data.get('ids')
        if not isinstance(client_ids, list):
            return Response({"error": "'ids' must be a list of UUIDs"}, status=400)
        try:
            client_ids = [UUID(str(i)) for i in client_ids]
        except ValueError:
            return Response({"error": "Invalid UUID in list"}, status=400)

    # 2. Get server detections
    server_detections = DetectionResult.objects.filter(user=user, is_deleted=False)
    server_ids = list(server_detections.values_list('server_id', flat=True))

    # 3. Detections missing on client
    missing_on_client = server_detections.filter(server_id__in=set(server_ids) - set(client_ids))

    # Format detections_to_send to match Kotlin structure
    detections_to_send = []
    for det in missing_on_client:
        detection_dict = {
            "detection": {
                "id": det.id,
                "userId": det.user.id,
                "serverId": str(det.server_id),
                "imageUri": det.image.url if det.image else "",
                "timestamp": det.timestamp if det.timestamp else 0,
                "isSynced": True,
                "detectionDate": det.detection_date if det.detection_date else 0,
                "note": det.note or ""
            },
            "boundingBoxes": []
        }

        for box in det.bounding_boxes.all():
            detection_dict["boundingBoxes"].append({
                "id": box.id,
                "detectionId": det.id,
                "x1": box.x1,
                "y1": box.y1,
                "x2": box.x2,
                "y2": box.y2,
                "cx": box.cx,
                "cy": box.cy,
                "w": box.w,
                "h": box.h,
                "cnf": box.cnf,
                "cls": box.cls,
                "clsName": box.cls_name,
            })

        detections_to_send.append(detection_dict)

    # 4. Detections missing on server
    missing_on_server = list(set(client_ids) - set(server_ids))

    return Response({
        "detections_to_send": detections_to_send,
        "detections_needed_from_phone": missing_on_server
    }, status=200)





import json
import os
import logging
from django.conf import settings
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def upload_detections_batch(request):
    logger.info("=== Starting batch upload ===")
    logger.info(f"MEDIA_ROOT: {settings.MEDIA_ROOT}")
    logger.info(f"MEDIA_URL: {settings.MEDIA_URL}")
    
    # Ensure media directories exist
    media_root = settings.MEDIA_ROOT
    images_dir = os.path.join(media_root, 'images')
    os.makedirs(images_dir, exist_ok=True)
    
    logger.info(f"Media root exists: {os.path.exists(media_root)}")
    logger.info(f"Images dir exists: {os.path.exists(images_dir)}")
    logger.info(f"Images dir writable: {os.access(images_dir, os.W_OK)}")

    # Get the raw form field for detections
    raw_detections = request.data.get('detections')

    if not raw_detections:
        return Response({'detections': ['This field is required.']}, status=400)

    try:
        detections = json.loads(raw_detections)
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON in detections'}, status=400)

    logger.info(f"Number of detections: {len(detections)}")
    logger.info(f"Files in request: {list(request.FILES.keys())}")

    # Map images like "image_0", "image_1" to their respective detection
    for i, det in enumerate(detections):
        image_key = det.get('image')  # e.g., "image_0"
        logger.info(f"Detection {i}: image_key={image_key}")
        
        if image_key and image_key in request.FILES:
            uploaded_file = request.FILES[image_key]
            logger.info(f"Found file for {image_key}: {uploaded_file.name}, size: {uploaded_file.size}")
            det['image'] = uploaded_file
        else:
            logger.warning(f"No file found for {image_key}")
            det['image'] = None  # Optional

    serializer = DetectionBatchSerializer(data={'detections': detections}, context={'user': request.user})

    if serializer.is_valid():
        logger.info("Serializer is valid, saving...")
        created = serializer.save()
        
        # Debug the saved instances
        for i, instance in enumerate(created):
            logger.info(f"=== Instance {i} Debug ===")
            logger.info(f"Server ID: {instance.server_id}")
            
            if hasattr(instance, 'image') and instance.image:
                logger.info(f"Image field name: {instance.image.name}")
                logger.info(f"Image field path: {instance.image.path}")
                logger.info(f"Image field URL: {instance.image.url}")
                
                # Check if file actually exists
                file_exists = os.path.exists(instance.image.path)
                logger.info(f"File exists on disk: {file_exists}")
                
                if file_exists:
                    file_size = os.path.getsize(instance.image.path)
                    logger.info(f"File size: {file_size} bytes")
                else:
                    logger.error(f"❌ FILE NOT FOUND: {instance.image.path}")
                    
                    # Check what files ARE in the directory
                    parent_dir = os.path.dirname(instance.image.path)
                    if os.path.exists(parent_dir):
                        files_in_dir = os.listdir(parent_dir)
                        logger.info(f"Files in {parent_dir}: {files_in_dir}")
                        
                        # Check if file exists with different name
                        expected_filename = os.path.basename(instance.image.path)
                        logger.info(f"Looking for: {expected_filename}")
                        
                        # List files that contain the server_id
                        matching_files = [f for f in files_in_dir if str(instance.server_id) in f]
                        logger.info(f"Files containing server_id: {matching_files}")
                    else:
                        logger.error(f"Parent directory doesn't exist: {parent_dir}")
            else:
                logger.info("No image field or image is None")
        
        read_serializer = DetectionResultReadSerializer(created, many=True)
        return Response(read_serializer.data, status=201)
    else:
        logger.error(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=400)
    
# views.py
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def soft_delete_detection(request, detection_id):
    try:
        detection = DetectionResult.objects.get(server_id=detection_id, user=request.user)
        detection.is_deleted = True
        detection.save()
        return Response({'status': 'detection soft deleted'}, status=200)
    except DetectionResult.DoesNotExist:
        return Response({'error': 'Detection not found'}, status=404)






@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_soft_deleted_detections(request):
    user = request.user
    deleted_ids = DetectionResult.objects.filter(user=user, is_deleted=True).values_list('server_id', flat=True)
    return Response({'deleted_ids': list(deleted_ids)}, status=200)




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_updated_notes(request):
    user = request.user
    detections = DetectionResult.objects.filter(user=user, is_deleted=False).exclude(note__isnull=True).exclude(note="")
    data = [
        {"server_id": detection.server_id, "note": detection.note}
        for detection in detections
    ]
    return Response({"notes": data}, status=200)





@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_notes(request):
    user = request.user
    updates = request.data.get('notes', [])

    updated = []

    for update in updates:
        detection_id = update.get('server_id')
        new_note = update.get('note')

        try:
            detection = DetectionResult.objects.get(server_id=detection_id, user=user)
            detection.note = new_note
            detection.save()
            updated.append(detection_id)
        except DetectionResult.DoesNotExist:
            continue

    return Response({"updated_ids": updated}, status=200)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([JSONParser])
def soft_delete_detections(request):
    try:
        server_ids = request.data.get('server_ids', [])

        if not isinstance(server_ids, list) or not server_ids:
            return Response({'error': 'server_ids must be a non-empty list.'}, status=400)

        # Filter detections matching server_ids
        detections = DetectionResult.objects.filter(server_id__in=server_ids)

        # Update isDeleted flag
        detections.update(is_deleted=True)

        return Response({'message': f'Successfully soft-deleted {detections.count()} detections.'}, status=200)

    except Exception as e:
        return Response({'error': str(e)}, status=500)
    



@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
@parser_classes([JSONParser])
def sync_detection_notes(request):
    user = request.user
    mobile_detections = request.data.get("detections", [])

    if not isinstance(mobile_detections, list):
        return Response({"error": "Invalid data format. Expected a list of detections."}, status=HTTP_400_BAD_REQUEST)

    detections_to_update_mobile = []

    for mobile_det in mobile_detections:
        if not isinstance(mobile_det, dict):
            continue

        server_id = mobile_det.get('serverId')
        mobile_updated_at = mobile_det.get('updatedAt')
        mobile_note = mobile_det.get('note')

        if not server_id or mobile_updated_at is None:
            continue

        try:
            detection = DetectionResult.objects.get(server_id=server_id, user=user, is_deleted=0)
            server_updated_at = detection.updated_at1

            # ✅ Skip if server_updated_at is None
            if server_updated_at is None:
                continue

            if mobile_updated_at > server_updated_at:
                detection.note = mobile_note
                detection.updated_at1 = mobile_updated_at
                detection.save()
            elif server_updated_at > mobile_updated_at:
                detections_to_update_mobile.append({
                    "serverId": str(detection.server_id),
                    "updatedAt": server_updated_at,
                    "note": detection.note
                })

        except DetectionResult.DoesNotExist:
            continue

    return Response({"detections": detections_to_update_mobile}, status=HTTP_200_OK)
