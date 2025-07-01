from django.urls import path
from . import views

urlpatterns = [
    path('app-info/', views.app_info, name='app_info'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('terms/', views.terms, name='terms'),
    path('account-deletion' , views.accountdel , name="privacy_policy"),
]