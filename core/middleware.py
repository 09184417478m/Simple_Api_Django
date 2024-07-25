from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken , TokenError
from core.models import TokenMetadata

class UserAgentMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if 'HTTP_AUTHORIZATION' in request.META:
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            if auth_header.startswith('Bearer '):
                token_str = auth_header.split(' ')[1]
                try:
                    token = UntypedToken(token_str)
                    outstanding_token = OutstandingToken.objects.get(token=token_str)
                    user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
                    metadata, created = TokenMetadata.objects.get_or_create(token=outstanding_token)
                    if metadata.user_agent != user_agent:
                        metadata.user_agent = user_agent
                        metadata.save()
                except (InvalidToken, TokenError, OutstandingToken.DoesNotExist):
                    pass
