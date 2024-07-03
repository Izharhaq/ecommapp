import datetime
import json
import jwt
from django.contrib.auth.models import Permission
from django.conf import settings
from rest_framework.authentication import SessionAuthentication

class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return






def get_jwt_payload(jwt_token):
    """
    Extract payload information from jwt_token by
    decoding jwt with secret key
    :param jwt_token:
    :return: Decoded jwt payload
    """
    try:
        payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms='HS256')
        return payload
    except:
        return
    

def generate_jwt_token(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.JWT_EXPIRY_TIME)
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    

# def generate_admin_token(json_data,mobile=None):
#     """
#     Generate jwt token for input json_data payload
#     :param json_data: payload contains admin_id UUID
#     :return: JWT token
#     """
#     from accounts.models import MyUser
#     if 'tenant' in json_data:
#         with schema_context(json_data['tenant']):
#             if mobile:
#                 json_data['exp'] = time.time() + settings.JWT_MOBILE_EXPIRY_TIME * 60
#             else:
#                 try:
#                     if MyUser.objects.filter(username=json_data['name']).values_list('token_expiry_time', flat=True).get() in ['None', None, '']:
#                         json_data['exp'] = time.time() + settings.JWT_EXPIRY_TIME * 60
#                     else:
#                         json_data['exp'] = time.time() + MyUser.objects.filter(username=json_data['name']).values_list('token_expiry_time', flat=True).get() * 60
#                 except Exception as error:
#                     logging.exception(error)
#                     json_data['exp'] = time.time() + settings.JWT_EXPIRY_TIME * 60
#     else:
#         if mobile:
#             json_data['exp'] = time.time() + settings.JWT_MOBILE_EXPIRY_TIME * 60
#         else:
#             json_data['exp'] = time.time() + settings.JWT_EXPIRY_TIME * 60

#     try:
#         token = jwt.encode(json_data, settings.SECRET_KEY, algorithm='HS256')
#         return token
#     except Exception as error:
#         logging.exception(error)
#         return False

def is_api_open():
    pass

def validate_jwt_token():
    pass