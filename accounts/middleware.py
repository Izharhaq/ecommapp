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

class TokenBlacklistMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth_header = request.headers.get('Authorization', None)
        if auth_header:
            token = auth_header.split(' ')[1]
            if TokenBlacklist.objects.filter(token=token).exists():
                return JsonResponse({"error": "Token is blacklisted"}, status=status.HTTP_401_UNAUTHORIZED)
