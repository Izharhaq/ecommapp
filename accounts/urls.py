from django.urls import path
from .views import LoginView, LogoutView, UserSignupView




urlpatterns = [

    path('login/', LoginView.as_view(), name="login"),  # open api
    path('logout/', LogoutView.as_view(), name="logout"),
    path('signup/', UserSignupView.as_view(), name='signup'), # open api
]
