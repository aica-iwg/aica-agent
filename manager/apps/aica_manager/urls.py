from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("modules", views.modules, name="modules"),
]
