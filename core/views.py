# core/views.py

from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.cache import cache
from .models import CustomUser
from .serializers import RegisterSerializer
from .sms_services import SmsServiceFactory
import random
from rest_framework.permissions import IsAuthenticated
import logging



class RegisterView(APIView):
    permission_classes = []
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = []
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):

    def post(self, request):

        try:
            token = RefreshToken(request.data.get('refresh'))
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class SendOtpView(APIView):
    permission_classes = []

    def post(self, request):
        phone = request.data.get('phone')
        if not phone:
            return Response({"error": "Phone number is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            sms_service = SmsServiceFactory.get_sms_service()
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        try:
            otp = random.randint(1000, 9999)
            cache.set(phone, otp, timeout=240)  # 4 minutes
            message = f"Your OTP is {otp}"
            sms_service.send_sms(phone, message)
            return Response({"message": "OTP sent successfully"}, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ValidateOtpView(APIView):

    def post(self, request):
        phone = request.data.get('phone')
        otp = request.data.get('otp')
        cached_otp = cache.get(phone)
        if cached_otp and str(cached_otp) == str(otp):
            try:
                user = CustomUser.objects.get(phone=phone)
                user.is_active = True
                user.save()
                return Response(status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):


    def post(self, request):
        user = request.user
        if not user.is_authenticated:
            return Response({"error": "User is not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        new_password_repeat = request.data.get('new_password_repeat')

        if new_password != new_password_repeat:
            return Response({"error": "New passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    permission_classes = []
    def post(self, request):
        phone = request.data.get('phone')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')
        new_password_repeat = request.data.get('new_password_repeat')

        if new_password != new_password_repeat:
            return Response({"error": "New passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        cached_otp = cache.get(phone)
        if cached_otp and str(cached_otp) == str(otp):
            try:
                user = CustomUser.objects.get(phone=phone)
                user.set_password(new_password)
                user.save()
                return Response({"password was set successfully"}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

class ListTokensView(APIView):


    def get(self, request):
        user = request.user
        tokens = OutstandingToken.objects.filter(user=user)
        token_list = [{"token_id": token.id, "user_agent": token.user_agent} for token in tokens]
        return Response(token_list, status=status.HTTP_200_OK)

class KillTokensView(APIView):


    def post(self, request):
        token_ids = request.data.get('token_ids', [])
        for token_id in token_ids:
            try:
                token = OutstandingToken.objects.get(id=token_id, user=request.user)
                BlacklistedToken.objects.get_or_create(token=token)
            except OutstandingToken.DoesNotExist:
                continue
        return Response(status=status.HTTP_200_OK)




#logger = logging.getLogger(__name__)
class TestAuthView(APIView):
    def get(self, request):
        # logger.debug(f"Request user: {request.user}")
        #logger.debug(f"Request headers: {request.headers}")

        user = request.user
        if not user.is_authenticated:
            return Response({"error": "User is not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({'user': user.username, 'is_authenticated': user.is_authenticated}, status=status.HTTP_200_OK)

