from django.urls import path
from .views import LoginView, UserRegisterView




urlpatterns = [

    path('login/', LoginView.as_view(), name="login"),
    # path("/api/logout/", LogoutView.as_view(), name="logout"),
    path('register/', UserRegisterView.as_view(), name='register'),
]
