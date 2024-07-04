import json
import datetime
import jwt
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import Permission
from rest_framework import permissions
from django.conf import settings
from rest_framework import status
from .models import MyUser, TokenBlacklist
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserLoginSerializer, UserRegisterSerializer
from accounts.utils import generate_jwt_token
from .permissions import IsAdminUser
from rest_framework.permissions import IsAuthenticated
from accounts.utils import CsrfExemptSessionAuthentication

class LoginView(APIView):
    authentication_classes = (CsrfExemptSessionAuthentication,) # for open API
    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token = generate_jwt_token(user)
            return Response({'token': token}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (CsrfExemptSessionAuthentication,)
    def post(self, request, *args, **kwargs):
        auth_header = request.headers.get('Authorization', None)

        if auth_header is None:
            return Response({"error": "No token provided"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Extract the token from the Authorization header
            token = auth_header.split(' ')[1]
            
            # Decode the token
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            
            # Add the token to blacklist
            TokenBlacklist.objects.create(token=token)
            
            return Response({"message": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)
        except jwt.ExpiredSignatureError:
            return Response({"error": "Token has already expired"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


    
class UserRegisterView(APIView):
    authentication_classes = (CsrfExemptSessionAuthentication,)
    permission_classes = [IsAuthenticated, IsAdminUser]
    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

