import token
from datetime import datetime, timezone
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.cache import cache
from core.models import OutstandingToken, TokenMetadata, CustomUser
from core.serializers import (
    ChangePasswordRequestSerializer,
    ChangePasswordSuccessResponseSerializer,
    ForgotPasswordRequestSerializer,
    KillTokensRequestSerializer,
    LoginRequestSerializer,
    PasswordSetSuccessfullyResponseSerializer,
    RegisterSerializer,
    SendOtpRequestSerializer,
    SendOtpResponseSerializer,
    LogoutRequestSerializer,
    TokenListResponseSerializer,
    TokenResponseSerializer,
    ValidateOtpRequestSerializer,
)
from core.sms_services import SmsServiceFactory
import random
from rest_framework.permissions import IsAuthenticated
import logging
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample ,inline_serializer,OpenApiResponse
from rest_framework import serializers



class RegisterView(APIView):
    permission_classes = []
    
    @extend_schema(
        request=RegisterSerializer,
        responses={201: dict(message="User registered successfully")}
    )

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
       


class LoginView(APIView):
    permission_classes = []

    @extend_schema(
        request=LoginRequestSerializer,
        responses={
            200: OpenApiResponse(response=TokenResponseSerializer, description='Token response'),
            404: OpenApiResponse(response=None, description='user not found')
        }
    )
    def post(self, request, *args, **kwargs):
            serializer = LoginRequestSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
           
            user = authenticate(request, username=serializer.validated_data['username'], password=serializer.validated_data['password'])
            
            if user is not None:
                    token = RefreshToken.for_user(user)
                    access_token = token.access_token
                    existing_token = OutstandingToken.objects.get(jti=token.payload['jti'])
                    user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
                    token_metadata = TokenMetadata(
                        token=existing_token,
                        user_agent=user_agent,
                    )
                    token_metadata.save()
                    token_response_serializer = TokenResponseSerializer(data={
                        'refresh': str(token),
                        'access': str(access_token),
                    })
                    token_response_serializer.is_valid(raise_exception=True)
                    return Response(token_response_serializer.data, status=status.HTTP_200_OK)
           
            return Response({"error":"user not found"} , status=status.HTTP_404_NOT_FOUND)
            



class LogoutView(APIView):

    @extend_schema(
        request=LogoutRequestSerializer,
        responses={
            205: None,
            400: OpenApiResponse(response=None, description='Bad request'),
        }
    )
    def post(self, request):
        try: 
            serializer = LogoutRequestSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)          
            token = RefreshToken(serializer.data.get("refresh"))
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)

        except rest_framework_simplejwt.exceptions.TokenError as e:
            return Response({"error":"invalid data"},status=status.HTTP_406_NOT_ACCEPTABLE)
        




class SendOtpView(APIView):
    permission_classes = []

    @extend_schema(
        request=SendOtpRequestSerializer,
        responses={
            200: OpenApiResponse(response=SendOtpResponseSerializer, description='OTP sent successfully'),
            400: OpenApiResponse(response=None, description='Bad request'),
            500: OpenApiResponse(response=None, description='Server error'),
        }
    )

   
    def post(self, request):

        serializer = SendOtpRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get('phone')

        try:
            sms_service = SmsServiceFactory.get_sms_service()
        except ValueError as e:
            
            return Response({"error":"Services are unavailabe"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        
        otp = random.randint(1000, 9999)
        cache.set(phone, otp, timeout=240)
        message = f"Your OTP is {otp}"
        sms_service.send_sms(phone, message)
       
        if cache.get(phone):

            response_serializer = SendOtpResponseSerializer(data={'message': 'OTP sent successfully'})
            response_serializer.is_valid(raise_exception=True)
            return Response(response_serializer.data, status=status.HTTP_200_OK)
    
        
        return Response({"error":"server can not respond.try later"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)





class ValidateOtpView(APIView):

   
    @extend_schema(
    request=ValidateOtpRequestSerializer,
    responses={
        200: None,
        400: OpenApiResponse(response=None, description='Invalid OTP'),
        404: OpenApiResponse(response=None, description='User not found'),
    }
)


    def post(self, request):
        serializer = ValidateOtpRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get('phone')
        otp = serializer.validated_data.get('otp')
        
        cached_otp = cache.get(phone)
        if cached_otp and str(cached_otp) == str(otp):
            return Response(status=status.HTTP_200_OK)
        
        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)





class ChangePasswordView(APIView):

    @extend_schema(
    request=ChangePasswordRequestSerializer,
    responses={
        200: OpenApiResponse(response=ChangePasswordSuccessResponseSerializer, description='Password changed successfully'),
        400: OpenApiResponse(response=None, description='Bad request'),
        401: OpenApiResponse(response=None, description='Unauthorized'),
    }
)

    def post(self, request):
        # Initialize the serializer with request data
        serializer = ChangePasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        new_password_repeat = serializer.validated_data['new_password_repeat']

     
        if new_password != new_password_repeat:
            return Response({"error":"new password is not equal to old password"}, status=status.HTTP_406_NOT_ACCEPTABLE)

      
        if not user.check_password(old_password):
            return Response({"error":"old password is not correct"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        user.set_password(new_password)
        user.save()

       
        success_serializer = ChangePasswordSuccessResponseSerializer(data={'message': 'Password changed successfully'})
        success_serializer.is_valid(raise_exception=True)
        return Response(success_serializer.data, status=status.HTTP_200_OK)
    




class ForgotPasswordView(APIView):
    permission_classes = []

    @extend_schema(
    request=ForgotPasswordRequestSerializer,
    responses={
        200: OpenApiResponse(response=PasswordSetSuccessfullyResponseSerializer, description='Password set successfully'),
        400: OpenApiResponse(response=None, description='Invalid OTP'),
        404: OpenApiResponse(response=None, description='User not found'),
    }
)

    def post(self, request):

        serializer = ForgotPasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data['phone']
        otp = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']
        new_password_repeat = serializer.validated_data['new_password_repeat']

        if new_password != new_password_repeat:
           return Response({"error":"new password is not equal to old password"}, status=status.HTTP_406_NOT_ACCEPTABLE)

       
        cached_otp = cache.get(phone)
        if cached_otp and str(cached_otp) == str(otp):
            try:
                user = CustomUser.objects.get(phone=phone)
                user.set_password(new_password)
                user.save()

                success_serializer = PasswordSetSuccessfullyResponseSerializer(data={"message": "Password set successfully"})
                success_serializer.is_valid(raise_exception=True)
                return Response(success_serializer.data, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({"error":"User not found"}, status=status.HTTP_404_NOT_FOUND)

       
        
        return Response({"error":"invalid inputs"} ,status=status.HTTP_406_NOT_ACCEPTABLE)





class ListTokensView(APIView):

    
    @extend_schema(
        responses={
            200: TokenListResponseSerializer(many=True)
        }
    )


    def get(self, request):
        user = request.user
        # todo : optimize query (prefetch related , select ...) **** prefetch_relates --> one_to_many , select_related --> many_to_one for handling foreghn key
        # tokens = OutstandingToken.objects.filter(user=user)
        # token_metadata = TokenMetadata.objects.filter(token_id__in=tokens.values_list('id', flat=True))
        tokens = OutstandingToken.objects.filter(user=user).prefetch_related('tokenmetadata_set')
        token_metadata = TokenMetadata.objects.filter(token_id__in=tokens.values_list('id', flat=True))

        token_list = [{"token_id": token.token_id, "user_agent": token.user_agent} for token in token_metadata]
        return Response(token_list, status=status.HTTP_200_OK)
    





#logger = logging.getLogger(__name__)
class KillTokensView(APIView):



    @extend_schema(
        request=KillTokensRequestSerializer,
        responses={
            200: None
        }
    )


    def post(self, request):
        token_ids = request.data.get('token_ids', [])

        # using bulk create , query set ,  optional
        # tokens = OutstandingToken.objects.filter(id__in=token_ids, user=request.user)
        # if not tokens.exists():
        # return Response(status=status.HTTP_404_NOT_FOUND)
        # Prepare the BlacklistedToken instances
        # blacklisted_tokens = [BlacklistedToken(token=token) for token in tokens] <--
        # Bulk create BlacklistedToken instances
        # BlacklistedToken.objects.bulk_create(blacklisted_tokens, ignore_conflicts=True)

        for token_id in token_ids:
            try:
                token = OutstandingToken.objects.get(id=token_id, user=request.user)
                BlacklistedToken.objects.get_or_create(token=token)
            except OutstandingToken.DoesNotExist:

                #logger.debug(f"Request user: {request.user}")
                #logger.debug(f"Request headers: {request.headers}")
                #logger.error(f"Token with ID {token_id} not found for user {request.user}")
                #logger.info(f"Tokens successfully processed for user {request.user}")
                continue
        return Response(status=status.HTTP_200_OK)





     
