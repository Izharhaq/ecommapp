from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Order
from .serializers import OrderSerializer
from accounts.utils import CsrfExemptSessionAuthentication
from accounts.permissions import IsReadAndEdit
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

User = get_user_model()

class OrderView(APIView):
    # permission_classes = [IsAuthenticated]
    '''
    def get(self, request, pk=None, format=None):
        if pk:
            # Retrieve a single product
            try:
                order = Order.objects.get(pk=pk)
                serializer = OrderSerializer(order)
                return Response(serializer.data)
            except Order.DoesNotExist:
                return Response({"message": "order not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            # List all orders
            orders = Order.objects.all()
            serializer = OrderSerializer(orders, many=True)
            return Response(serializer.data)
    '''
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        if request.user.is_admin:
            if pk:
                order = Order.objects.get(pk=pk)
                serializer = OrderSerializer(order)
            else:
                orders = Order.objects.all()
                serializer = OrderSerializer(orders, many=True)
        else:
            orders = Order.objects.filter(user=request.user)
            serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


    authentication_classes = (CsrfExemptSessionAuthentication,)
    def post(self, request, format=None):
        
        # Create a new order
        serializer = OrderSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user) 
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, format=None):
        if not request.user.is_admin:
            return Response(status=status.HTTP_403_FORBIDDEN)
        try:
            order = Order.objects.get(pk=pk)
        except Order.DoesNotExist:
            return Response({'message':'Order not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = OrderSerializer(order, data=request.data, partial=True) # partial = True for updating data(it won't create a new entry in db)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    """    def delete(self, request, pk, format=None):
        # Delete an order
        if not request.user.role_id == 3:
            return Response({"detail": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)

        try:
            order = Order.objects.get(pk=pk)
            order.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Order.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
            
    """
        
    def delete(self, request, pk):
        if not request.user.is_admin:
            return Response({'msg':'permission denied to delete order'}, status=status.HTTP_403_FORBIDDEN)
        try:
            order = Order.objects.get(pk=pk)
            order.delete()
            return Response({'msg':'order deleted successfully.'},status=status.HTTP_204_NO_CONTENT)
        except Order.DoesNotExist:
            return Response({'msg':'order not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        
