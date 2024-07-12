import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from ecommapp.settings import JWT_EXPIRY_TIME


    
    
    
class MyUser(AbstractUser):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('admin', 'Admin'),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    username=models.CharField(max_length=50, unique=True, primary_key=True)
    email=models.EmailField(max_length=100, unique=True)
    password=models.CharField(max_length=100, null=True, blank=True)
    first_name=models.CharField(max_length=50)
    last_name=models.CharField(max_length=50, null=True, blank=True)
    phone_no=models.CharField(max_length=10, blank=True)
    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=True)
    is_admin=models.BooleanField(null= True, default=False)
    
    groups = models.ManyToManyField(Group,related_name='myuser_set',blank=True,help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',related_query_name='user')
    user_permissions = models.ManyToManyField(Permission,related_name='myuser_set',blank=True,help_text='Specific permissions for this user.',related_query_name='user')


    def __str__(self):
        return self.username


class TokenExpired(models.Model):
    token = models.CharField(max_length=500)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.token
    
class MyUserToken(models.Model):
    token_id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)