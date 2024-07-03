import jwt
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from accounts.utils import is_api_open, validate_jwt_token

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

# class AuthenticationAuthorisationMiddleware(object):
#     def __init__(self, get_response):
#         self.get_response = get_response
#         self.is_valid = False
#         self.jwt = False
#         self.role = None


#     def __call__(self, request):
#         if not is_api_open(request):
#             self.jwt = request.META.get('HTTP_AUTHORIZATION', None)
#             self.is_valid = validate_jwt_token(self.jwt)

