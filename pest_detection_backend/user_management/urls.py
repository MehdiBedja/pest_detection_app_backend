# from django.contrib import admin
from django.urls import path, re_path
from . import views

urlpatterns = [
    # path('admin/', admin.site.urls),
    re_path('login', views.login),
    re_path('signup', views.signup),
    re_path('get_user_info', views.get_user_info),
    re_path('change_password', views.change_password),
    re_path('logout', views.logout),
    re_path('googlesignup', views.google_signup),
    re_path('test' , views.test_connection) ,
    re_path('google_sign_in' , views.google_sign_in),


    
    re_path(r'^getUser/(?P<id>\d+)/$', views.custom_user_detail, name='customuser-detail'),
    re_path(r'^google/?$', views.google_login),



    # re_path('test_token', views.test_token)
]
