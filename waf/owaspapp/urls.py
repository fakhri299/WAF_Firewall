# owaspapp/urls.py
from django.urls import path
from .views import attack_info,dashboard
from account import views

urlpatterns = [
    path('attack-info/', attack_info, name='attack_info'),
    path('dashboard/', dashboard, name='dashboard'),
    path('register/', views.register ,name="register" ),
    
]
