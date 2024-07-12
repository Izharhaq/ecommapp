"""
import jwt
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from accounts.utils import is_api_open, validate_jwt_token
from .models import TokenBlacklist
from rest_framework import status
from django.http import JsonResponse


class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', None)
        if auth_header:
            try:
                prefix, token = auth_header.split(' ')
                if prefix.lower() == 'bearer':
                    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                    user_id = payload.get('user_id')
                    user = get_user_model().objects.get(id=user_id)
                    request.user = user
            except jwt.ExpiredSignatureError:
                request.user = AnonymousUser()
            except jwt.DecodeError:
                request.user = AnonymousUser()
            except get_user_model().DoesNotExist:
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()

"""



#######################


import json
import datetime
import logging
from django.http import JsonResponse
from django.contrib.auth import login
from django.contrib.contenttypes.models import ContentType
from rest_framework import status
from rest_framework.status import HTTP_401_UNAUTHORIZED

from accounts.models import MyUser, MyUserToken
from accounts.utils import is_api_open, rotate_jwt_token, validate_jwt_token,get_jwt_payload, get_expired_jwt_payload_, generate_admin_token
from utils.api_response_keys import TOKEN_EXPIRED, UNAUTHORISED_ACCESS


class AuthenticationAuthorisationMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
        self.is_valid = False
        self.jwt = False
        self.role = None

    def __call__(self, request):
        if not is_api_open(request):
            self.jwt = request.META.get('HTTP_AUTHORIZATION', None)

            if not self.jwt:
                return JsonResponse({"status": HTTP_401_UNAUTHORIZED, "error": UNAUTHORISED_ACCESS})

            self.is_valid = validate_jwt_token(self.jwt)
            try:
                if self.is_valid:
                        token = get_jwt_payload(self.jwt)
                        if token['tenant'] != request.tenant.schema_name:
                            return JsonResponse({"status": HTTP_401_UNAUTHORIZED, "error": UNAUTHORISED_ACCESS})
            except Exception as error:
                    # need to add logger here
                    logging.exception(error)
                    return JsonResponse({"status": HTTP_401_UNAUTHORIZED, "error": UNAUTHORISED_ACCESS})
            
        response = self.get_response(request)
        return response



from django.utils.deprecation import MiddlewareMixin
from .models import TokenExpired
class TokenExpiredMiddleware(MiddlewareMixin):
    def process_request(self, request):
        token = request.headers.get('Authorization')
        # token = request.META.get('HTTP_AUTHORIZATION')  # or request.headers.get('Authorization')
        if token and TokenExpired.objects.filter(token=token).exists():
            return JsonResponse({'error': 'Token is expired.'}, status=401)
        return None
