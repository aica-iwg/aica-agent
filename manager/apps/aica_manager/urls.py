"""
This module defines the URLs for the Django web frontend

Classes: None
Functions: None
"""

from django.urls import path

from . import views

urlpatterns = [
    path("modules", views.modules, name="modules"),
]
