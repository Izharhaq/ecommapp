import json
import datetime
import jwt
import logging
from ast import literal_eval
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import Permission
from rest_framework import permissions
from rest_framework import status
from rest_framework.status import HTTP_403_FORBIDDEN
from django.conf import settings
from django.contrib.auth import authenticate
from .models import MyUser, TokenExpired
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserLoginSerializer, UserRegisterSerializer
from accounts.utils import generate_admin_token
from .permissions import IsAdminUser
from rest_framework.permissions import IsAuthenticated
from accounts.utils import CsrfExemptSessionAuthentication
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from utils.api_response_keys import (
    INVALID_REQUEST
)
from ecommapp.constants import ADMIN_USERNAME
from rest_framework.response import Response


class LoginView(APIView):
    # authentication_classes = (CsrfExemptSessionAuthentication,) # for open API
    # def post(self, request, *args, **kwargs):
    #     serializer = UserLoginSerializer(data=request.data)
    #     if serializer.is_valid():
    #         user = serializer.validated_data['user']
    #         token = generate_jwt_token(user)
    #         return Response({'token': token}, status=status.HTTP_200_OK)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    authentication_classes = (CsrfExemptSessionAuthentication,)
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['username', 'password'],
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={200: 'Data Found', 500: 'Internal Server error'},
    )

    def post(self, request):
        """
        Authentication API
        :param request:
        :return: JWT if True else return Invalid request/Admin login invalid credential
        """
        from accounts.serializers import UserSerializer
        from accounts.utils import encrypt_, decrypt_

        # password = SECRET_KEY_FOR_LICENSE.encode()
        auth_token = response.headers['Authorization']
        try:
            if 'username' in request.data:
                requestdata = request.data
            else:
                requestdata = literal_eval(
                    decrypt_(request.data).decode('utf-8')
                )
            if requestdata["username"] == ADMIN_USERNAME:
                user = authenticate(
                    username=requestdata["username"],
                    password=requestdata["password"],
                )
        except Exception as error:
            logging.exception(error)
            return Response(encrypt_(str(json.dumps({"status": HTTP_403_FORBIDDEN, "error": INVALID_REQUEST}))))
        return Response({"status": 200, "message": "Success"})  
        # return Response(
        #                 encrypt_(str(json.dumps(data)),
        #                 headers={
        #                     "Access-Control-Expose-Headers": "Authorization, X-Custom-header",
        #                     "Authorization": access_token,
        #                 },
        #             ) )           





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
            
            # Add the expired token
            TokenExpired.objects.create(token=token)
            
            return Response({"message": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)
        except jwt.ExpiredSignatureError:
            return Response({"error": "Token has already expired"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


    
class UserSignupView(APIView):
    authentication_classes = (CsrfExemptSessionAuthentication,)
    permission_classes = [IsAuthenticated, IsAdminUser]
    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

