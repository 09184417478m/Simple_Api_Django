from rest_framework.authtoken.models import Token
from django.contrib import admin
from .models import CustomUser , TokenMetadata


admin.site.register(CustomUser)
admin.site.register(Token)
admin.site.register(TokenMetadata)