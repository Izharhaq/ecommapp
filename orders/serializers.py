from rest_framework import serializers
from .models import Order

class OrderSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')
    is_admin = serializers.SerializerMethodField()

    
    class Meta:
        model = Order
        fields = '__all__'

    def get_is_admin(self, obj):
        return obj.owner.is_staff or obj.owner.is_superuser
