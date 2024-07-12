from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Product
from .serializers import ProductSerializer
from accounts.utils import CsrfExemptSessionAuthentication
from rest_framework import status
from accounts.permissions import IsReadAndEdit
from rest_framework.permissions import IsAuthenticated




class ProductView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None, format=None):
        if pk:
            # Retrieve a single product
            try:
                product = Product.objects.get(pk=pk)
                serializer = ProductSerializer(product)
                return Response(serializer.data)
            except Product.DoesNotExist:
                return Response({"message": "product not found"}, status=status.HTTP_404_NOT_FOUND)
            
        else:
            # List all products
            products = Product.objects.all()
            serializer = ProductSerializer(products, many=True)
            return Response(serializer.data)

    authentication_classes = (CsrfExemptSessionAuthentication,)
    def post(self, request, format=None):
        if not request.user.role == 'admin':
            return Response({'msg':'permission denied to add a product'}, status=status.HTTP_403_FORBIDDEN)
        # Create a new product
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user) 
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def put(self, request, pk, format=None):
        if not request.user.role == 'admin':
            return Response({'msg':'permission denied to change product details'}, status=status.HTTP_403_FORBIDDEN)
        # Update an existing product
        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return Response({'msg':'product not found !'},status=status.HTTP_404_NOT_FOUND)
        
        serializer = ProductSerializer(product, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        # Delete a product
        if not request.user.role == 'admin':
            return Response({"message": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        try:
            product = Product.objects.get(pk=pk)
            product.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Product.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)