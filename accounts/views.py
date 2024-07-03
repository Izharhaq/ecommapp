import json
import datetime

from rest_framework.authtoken.models import Token
from django.contrib.auth.models import Permission
from rest_framework import permissions
from django.conf import settings

from rest_framework import status
from .models import MyUser

from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserLoginSerializer, UserRegisterSerializer
from accounts.utils import generate_jwt_token
# from accounts.utils import generate_admin_token


class LoginView(APIView):

    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token = generate_jwt_token(user)
            return Response({'token': token}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class LogoutView(APIView):
#     pass
    
class UserRegisterView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            print("Serializer is valid")
            serializer.save()
            print("Serializer is saved now")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

