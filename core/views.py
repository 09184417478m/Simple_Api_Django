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
from .models import CustomUser, TokenMetadata
from .serializers import RegisterSerializer
from .sms_services import SmsServiceFactory
import random
from rest_framework.permissions import IsAuthenticated
import logging
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample ,inline_serializer
from rest_framework import serializers



class RegisterView(APIView):
    permission_classes = []
    
    @extend_schema(
        request=RegisterSerializer,
        responses={201: dict(message="User registered successfully"), 400: dict(error="Bad request")}
    )

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        # below code to be alternative to lines 38 to 41 
        # serializer.is_valid(raise_exception=True)
        # serializer.save()
        # return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = []

    @extend_schema(
        request=inline_serializer(
            name='LoginRequest',
            fields={
                'username': serializers.CharField(),
                'password': serializers.CharField(),
            }
        ),
        responses={
            200: inline_serializer(
                name='TokenResponse',
                fields={
                    'refresh': serializers.CharField(),
                    'access': serializers.CharField(),
                }
            ),
            401: inline_serializer(
                name='InvalidCredentialsResponse',
                fields={
                    'detail': serializers.CharField(),
                }
            ),
        }
    )
    def post(self, request, *args, **kwargs):
        user = authenticate(request, username=request.data['username'], password=request.data['password'])

        if user is not None:

            token = RefreshToken.for_user(user)

            access_token = token.access_token

            existing_token = OutstandingToken.objects.get(
                jti=token.payload['jti']
            )
    

            user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')

            token_metadata = TokenMetadata(
                token=existing_token,
                user_agent=user_agent,
            )
            token_metadata.save()

            return Response({
                'refresh': str(token),
                'access': str(access_token),
            })
        else:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
class LogoutView(APIView):

    @extend_schema(
        request=inline_serializer(
            name='LogoutRequest',
            fields={
                'refresh': serializers.CharField(),
            }
        ),
        responses={
            205: None,
            400: inline_serializer(
                name='BadRequestResponse',
                fields={
                    'error': serializers.CharField(),
                }
            ),
        }
    )

    def post(self, request):

        try:
            token = RefreshToken(request.data.get('refresh'))
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class SendOtpView(APIView):
    permission_classes = []

    @extend_schema(
        request=inline_serializer(
            name='SendOtpRequest',
            fields={
                'phone': serializers.CharField(),
            }
        ),
        responses={
            200: inline_serializer(
                name='SendOtpResponse',
                fields={
                    'message': serializers.CharField(),
                }
            ),
            400: inline_serializer(
                name='BadRequestResponse',
                fields={
                    'error': serializers.CharField(),
                }
            ),
            500: inline_serializer(
                name='ServerErrorResponse',
                fields={
                    'error': serializers.CharField(),
                }
            )
        }
    )

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

    @extend_schema(
        request=inline_serializer(
            name='ValidateOtpRequest',
            fields={
                'phone': serializers.CharField(),
                'otp': serializers.CharField(),
            }
        ),
        responses={
            200: None,
            400: inline_serializer(
                name='InvalidOtpResponse',
                fields={
                    'error': serializers.CharField(),
                }
            ),
            404: inline_serializer(
                name='UserNotFoundResponse',
                fields={
                    'error': serializers.CharField(),
                }
            ),
        }
    )


    def post(self, request):
        phone = request.data.get('phone')
        otp = request.data.get('otp')
        cached_otp = cache.get(phone)
        if cached_otp and str(cached_otp) == str(otp):
            # try:
            #     user = CustomUser.objects.get(phone=phone)
            #     #user.is_active = True
            #     user.save()
            return Response(status=status.HTTP_200_OK)
            # except CustomUser.DoesNotExist:
            #    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):

    @extend_schema(
        request=inline_serializer(
            name='ChangePasswordRequest',
            fields={
                'old_password': serializers.CharField(),
                'new_password': serializers.CharField(),
                'new_password_repeat': serializers.CharField(),
            }
        ),
        responses={
            200: inline_serializer(
                name='ChangePasswordSuccessResponse',
                fields={
                    'message': serializers.CharField(),
                }
            ),
            400: inline_serializer(
                name='BadRequestResponse',
                fields={
                    'error': serializers.CharField(),
                }
            ),
            401: inline_serializer(
                name='UnauthorizedResponse',
                fields={
                    'error': serializers.CharField(),
                }
            )
        }
    )

    def post(self, request):
        user = request.user

        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        new_password_repeat = request.data.get('new_password_repeat')

        if new_password != new_password_repeat:
            return Response({"error": "New passwords do not match"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        user.set_password(new_password)
        user.save()
        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    permission_classes = []

    @extend_schema(
        request=inline_serializer(
            name='ForgotPasswordRequest',
            fields={
                'phone': serializers.CharField(),
                'otp': serializers.CharField(),
                'new_password': serializers.CharField(),
                'new_password_repeat': serializers.CharField(),
            }
        ),
        responses={
            200: inline_serializer(
                name='PasswordSetSuccessfullyResponse',
                fields={
                    'message': serializers.CharField(),
                }
            ),
            400: inline_serializer(
                name='InvalidOtpResponse',
                fields={
                    'error': serializers.CharField(),
                }
            ),
            404: inline_serializer(
                name='UserNotFoundResponse',
                fields={
                    'error': serializers.CharField(),
                }
            ),
        }
    )

    def post(self, request):
        phone = request.data.get('phone')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')
        new_password_repeat = request.data.get('new_password_repeat')

        if new_password != new_password_repeat:
            return Response({"error": "New passwords do not match"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        cached_otp = cache.get(phone)
        if cached_otp and str(cached_otp) == str(otp):
            try:
                user = CustomUser.objects.get(phone=phone)
                user.set_password(new_password)
                user.save()
                return Response({"password was set successfully"}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"error": "Invalid OTP"}, status=status.HTTP_406_NOT_ACCEPTABLE)

class ListTokensView(APIView):

    @extend_schema(
        responses={
            200: inline_serializer(
                name='TokenListResponse',
                fields={
                    'token_id': serializers.IntegerField(),
                    'user_agent': serializers.CharField(),
                },
                many=True
            )
        }
    )
    def get(self, request):
        user = request.user
        # todo : optimize query (prefetch related , select ...) **** prefetch_relates --> one_to_many , select_related --> many_to_one for handling foreghn key
        tokens = OutstandingToken.objects.filter(user=user).prefetch_related('tokenmetadata_set')
        token_metadata = TokenMetadata.objects.filter(token_id__in=tokens.values_list('id', flat=True))

        # tokens = OutstandingToken.objects.filter(user=user)
        # token_metadata = TokenMetadata.objects.filter(token_id__in=tokens.values_list('id', flat=True))
        token_list = [{"token_id": token.token_id, "user_agent": token.user_agent} for token in token_metadata]
        return Response(token_list, status=status.HTTP_200_OK)

class KillTokensView(APIView):

    @extend_schema(
        request=inline_serializer(
            name='KillTokensRequest',
            fields={
                'token_ids': serializers.ListField(
                    child=serializers.IntegerField()
                )
            }
        ),
        responses={
            200: None
        }
    )

    def post(self, request):
        # using bulk create , query set ,  optional
        #  tokens = OutstandingToken.objects.filter(id__in=token_ids, user=request.user)

        # if not tokens.exists():
        #     return Response(status=status.HTTP_404_NOT_FOUND)

        # # Prepare the BlacklistedToken instances
        # blacklisted_tokens = [BlacklistedToken(token=token) for token in tokens] <--

        # # Bulk create BlacklistedToken instances
        # BlacklistedToken.objects.bulk_create(blacklisted_tokens, ignore_conflicts=True)
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

    @extend_schema(
        responses={
            200: inline_serializer(
                name='AuthSuccessResponse',
                fields={
                    'user': serializers.CharField(),
                    'is_authenticated': serializers.BooleanField(),
                }
            ),
            401: inline_serializer(
                name='AuthErrorResponse',
                fields={
                    'error': serializers.CharField(),
                }
            ),
        }
    )

    def get(self, request):
        # logger.debug(f"Request user: {request.user}")
        #logger.debug(f"Request headers: {request.headers}")

        user = request.user
        if not user.is_authenticated:
            return Response({"error": "User is not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({'user': user.username, 'is_authenticated': user.is_authenticated}, status=status.HTTP_200_OK)

