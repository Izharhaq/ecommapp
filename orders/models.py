from django.db import models

class Order(models.Model):
    product_name = models.CharField(max_length=255)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    ordered_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return self.product_name


