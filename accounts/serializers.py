from rest_framework import serializers
from datetime import timedelta
from .models import MyUser
from django.contrib.auth.models import Permission



from django.contrib.auth import authenticate
from rest_framework import serializers

class UserLoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(max_length=128, write_only=True)

    class Meta:
        model = MyUser
        fields = ['username', 'password']

    def validate(self, data):
        username = data.get("username", "")
        password = data.get("password", "")

        if username and password:
            user = authenticate(username=username, password=password)
            if user is None:
                raise serializers.ValidationError("Invalid credentials")
            data['user'] = user
        else:
            raise serializers.ValidationError("Must include username and password")
        
        return data
    
class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = MyUser
        fields = ['first_name', 'last_name', 'username', 'password', 'phone_no']


    def create(self, validated_data):
        user = MyUser(
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_no=validated_data['phone_no']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

