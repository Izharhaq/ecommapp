from django.db import models

# Create your models here.
# from datetime import datetime
from django.contrib.auth.models import AbstractUser, Group, Permission
from ecommapp.settings import JWT_EXPIRY_TIME
# from accounts.utils import get_jwt_payload


    
    
    
class MyUser(AbstractUser):
    username=models.CharField(max_length=50, unique=True)
    first_name=models.CharField(max_length=5)
    last_name=models.CharField(max_length=50, null=True, blank=True)
    password=models.CharField(max_length=100, null=True, blank=True)
    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=True)
    is_admin=models.BooleanField(null= True, default=False)
    phone_no=models.CharField(max_length=10, blank=True)
    # token_expiry_time = models.IntegerField(null=True, blank=True, default=JWT_EXPIRY_TIME)
    groups = models.ManyToManyField(Group,related_name='myuser_set',blank=True,help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',related_query_name='user')
    user_permissions = models.ManyToManyField(Permission,related_name='myuser_set',blank=True,help_text='Specific permissions for this user.',related_query_name='user')

    # class Meta:
    #     verbose_name = 'user'
    #     verbose_name_plural = 'users'

    def __str__(self):
        return self.username
