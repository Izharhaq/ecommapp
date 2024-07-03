from rest_framework import serializers
from .models import Product

class ProductSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')
    is_admin = serializers.SerializerMethodField()
    
    class Meta:
        model = Product
        fields = '__all__'


    def get_is_admin(self, obj):
        return obj.owner.is_staff or obj.owner.is_superuser