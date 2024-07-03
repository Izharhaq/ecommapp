from django.urls import path
from .views import ProductView


urlpatterns = [
    path('', ProductView.as_view(), name='products_list'),      # To get list and add products
    path('<int:pk>/', ProductView.as_view(), name='products_list'),     #To get a product detail
    

]
