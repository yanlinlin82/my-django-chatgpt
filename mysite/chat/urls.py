from django.urls import path
from . import views

urlpatterns = [
    path('wx/', views.wx, name='wx'),
]