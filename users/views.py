from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import EmailVerification, User
from .serializers import UserCreateSerializer, UserLoginSerializer


class UserCreateView(APIView):
    """
    Create a new user in the system
    """
    def post(self, request):
        """
        Create a new user with a given email and password
        """
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(ObtainAuthToken):
    """
    Create a new auth token for user
    """
    serializer_class = UserLoginSerializer
    def post(self, request, *args, **kwargs):
        """handle creating user authentication tokens"""
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)

        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        }, status=status.HTTP_200_OK)

class EmailVerifyView(APIView):
    """
    Verify email address
    """
    def get(self, request):
        """
        Verify email address
        """
        #get the token from query params
        token = request.query_params.get('token')
        try:
            email_conf = EmailVerification.objects.get(key=token)
            if email_conf.user.email_verified:
                return Response({'message': 'Email already verified'}, status=status.HTTP_400_BAD_REQUEST)
            elif email_conf.is_expired:
                return Response({'message': 'Token expired, a new token will be sent to your mail'}, status=status.HTTP_400_BAD_REQUEST)
            elif email_conf.verify():
                return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Something went wrong'}, status=status.HTTP_400_BAD_REQUEST)
        except EmailVerification.DoesNotExist:
            return Response({'message': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)