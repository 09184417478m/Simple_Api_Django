from rest_framework import serializers
from core.models import CustomUser

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
    



class LoginRequestSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class TokenResponseSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()

class LogoutRequestSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class SendOtpRequestSerializer(serializers.Serializer):
    phone = serializers.CharField()

class SendOtpResponseSerializer(serializers.Serializer):
    message = serializers.CharField()

class ValidateOtpRequestSerializer(serializers.Serializer):
    phone = serializers.CharField()
    otp = serializers.CharField()

class ChangePasswordRequestSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    new_password_repeat = serializers.CharField()

class ChangePasswordSuccessResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class ForgotPasswordRequestSerializer(serializers.Serializer):
    phone = serializers.CharField()
    otp = serializers.CharField()
    new_password = serializers.CharField()
    new_password_repeat = serializers.CharField()

class PasswordSetSuccessfullyResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class TokenListResponseSerializer(serializers.Serializer):
    token_id = serializers.IntegerField()
    user_agent = serializers.CharField()

class KillTokensRequestSerializer(serializers.Serializer):
    token_ids = serializers.ListField(
        child=serializers.IntegerField()
    )