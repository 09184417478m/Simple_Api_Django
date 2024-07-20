from rest_framework import serializers
from .models import CustomUser

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'phone']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            phone=validated_data['phone']
        )
        return user
    



    

"""
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()





class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()




class SendOtpSerializer(serializers.Serializer):
    phone = serializers.CharField()


.
.
.
"""