from rest_framework import serializers
from rest_framework.authtoken.serializers import AuthTokenSerializer
from .models import User, AdminUser
from django.contrib.auth import authenticate

class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'email',
            'first_name',
            'last_name',
            'password'
        ]
    def validate(self, data):
        """
            Contains the following validations:
            the password needs to be at least 8 characters long
            must contain numbers and letters both uppercase and lowercase
        """
        if len(data['password']) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters long')
        if not any(char.isdigit() for char in data['password']):
            raise serializers.ValidationError('Password must contain at least one number')
        if not any(char.isupper() for char in data['password']):
            raise serializers.ValidationError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in data['password']):
            raise serializers.ValidationError('Password must contain at least one lowercase letter')
        return data
        return data
    
    def save(self):
        """
            Creates a new user
        """
        user = User(
            email=self.validated_data['email'],
            first_name=self.validated_data['first_name'],
            last_name=self.validated_data['last_name'],
        )
        password = self.validated_data['password']
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(label='email')
    password = serializers.CharField(
        label='password',
        style={'input_type': 'password'},
        trim_whitespace=False
    )
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)
            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)

            if not user:
                msg = ('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
            if not user.is_active:
                msg = ('User account is disabled.')
                raise serializers.ValidationError(msg, code='authorization')
            if not user.email_verified:
                #deauthenticate the user
                user = None
                msg = ('User email is not verified.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = ('Must include "email" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs

class AdminCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdminUser
        fields = [
            'email',
            'first_name',
            'last_name',
            'password'
        ]

    def save(self):
        user = AdminUser(
            email=self.validated_data['email'],
            first_name=self.validated_data['first_name'],
            last_name=self.validated_data['last_name'],
        )
        password = self.validated_data['password']
        user.set_password(password)
        user.save()
        return user


