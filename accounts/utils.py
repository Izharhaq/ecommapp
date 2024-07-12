import datetime, time
import json
import jwt
import logging
from django.contrib.auth.models import Permission
from django.conf import settings
from django.urls import resolve
from tenant_schemas.utils import schema_context

from rest_framework.authentication import SessionAuthentication

class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return




def generate_admin_token(json_data,mobile=None):
    """
    Generate jwt token for input json_data payload
    :param json_data: payload contains admin_id UUID
    :return: JWT token
    """
    from accounts.models import MyUser
    if 'tenant' in json_data:
        with schema_context(json_data['tenant']):
            if mobile:
                json_data['exp'] = time.time() + settings.JWT_MOBILE_EXPIRY_TIME * 60
            else:
                try:
                    if MyUser.objects.filter(username=json_data['name']).values_list('token_expiry_time', flat=True).get() in ['None', None, '']:
                        json_data['exp'] = time.time() + settings.JWT_EXPIRY_TIME * 60
                    else:
                        json_data['exp'] = time.time() + MyUser.objects.filter(username=json_data['name']).values_list('token_expiry_time', flat=True).get() * 60
                except Exception as error:
                    logging.exception(error)
                    json_data['exp'] = time.time() + settings.JWT_EXPIRY_TIME * 60
    else:
        if mobile:
            json_data['exp'] = time.time() + settings.JWT_MOBILE_EXPIRY_TIME * 60
        else:
            json_data['exp'] = time.time() + settings.JWT_EXPIRY_TIME * 60

    try:
        token = jwt.encode(json_data, settings.SECRET_KEY, algorithm='HS256')
        return token
    except Exception as error:
        logging.exception(error)
        return False

def get_expired_jwt_payload_(jwt_token):
    """
    Extract payload information from jwt_token by
    decoding jwt with secret key
    :param jwt_token:
    :return: Decoded jwt payload
    """
    try:
        payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms='HS256',verify=False)
        return payload
    except:
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
    
def is_api_open(request):
    """
    Validate open api request which does not need any http authorization token
    and login like contact_us, about_us
    :param request:
    :return: True if request.path is in open api dict
    """
    if request.path.startswith('/login/') or request.path.startswith('/signup/'):
        return True
    else:
        return settings.OPEN_API.get(resolve(request.path).url_name, False) # added False 


def rotate_jwt_token(jwt_token):
    """
    Generate new jwt for same user and extended expiry
    time without login request
    :param jwt_token:
    :return:
    """
    try:
        payload = get_jwt_payload(jwt_token)
        return generate_admin_token(payload)
    except:
        return


def validate_jwt_token(jwt_token):
    """
    Validate passed jwt parameter
    :param jwt_token:
    :return: 'JWT_ROTATE','JWT_VALID',False
    """
    try:
        payload = get_jwt_payload(jwt_token)
        if time.time() > (payload['exp'] - (settings.JWT_TOKEN_ROTATE_TIME * 60)):

            return {'JWT_ROTATE': payload}
        else:
            return {'JWT_VALID': payload}
    except:
        return False    





def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

from Cryptodome import Random
from Cryptodome.Cipher import AES
import base64
from hashlib import md5
BLOCK_SIZE = 16

def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return (data + (chr(length)*length)).encode()

def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

def bytes_to_key(data, salt, output=48):
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]



def encrypt_(message, passphrase):
    salt = Random.new().read(8)
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))

def decrypt_(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))




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

# def is_api_open():
#     pass

# def validate_jwt_token():
#     pass