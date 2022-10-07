from django.urls import path

from . import views

urlpatterns = [
    path("", views.overview, name="overview"),
    path("modules", views.modules, name="modules"),
]
