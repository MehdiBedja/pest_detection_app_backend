from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path("admin/", admin.site.urls),
   #path('image_management/', include('image_management.urls')),  # Include app-specific URLs
    path('user_management/', include('user_management.urls')) , # Include your app's URL configuration
    path('detection/' , include('detection.urls'))

]  + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)