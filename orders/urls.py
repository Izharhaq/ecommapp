from django.urls import path
from .views import OrderView

urlpatterns = [

    path('', OrderView.as_view(), name='orders-list-add'),      # To get list and add orders
    path('<int:pk>/', OrderView.as_view(), name='orders-retrieve-update-delete'),     #To update -delete an order
    
]