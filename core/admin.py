from rest_framework.authtoken.models import Token
from django.contrib import admin
from .models import CustomUser


admin.site.register(CustomUser)
admin.site.register(Token)
