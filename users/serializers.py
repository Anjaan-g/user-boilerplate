from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import update_last_login
from django.db.models import ObjectDoesNotExist
from django.utils.decorators import method_decorator
from rest_framework import serializers
from rest_framework_simplejwt.serializers import (TokenObtainPairSerializer,
                                                  TokenObtainSerializer)
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    email = serializers.EmailField()
    phone_no = serializers.CharField()
    password = serializers.CharField(min_length=8, write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ('id', 'user_uuid', 'username', 'first_name', 'last_name', 'email', 'phone_no', 'role',
                 'is_superuser', 'is_admin',
                  'password', )
        lookup_field = 'username'
        read_only_fields = (
        'id', 'is_superuser', 'is_admin')

    def get_queryset(self):
        if self.request.user.is_staff:
            return CustomUser.objects.all()
        else:
            return self.request.user

    def create(self, validated_data):
        user = CustomUser(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_no=validated_data['phone_no'],
            user_uuid=validated_data['user_uuid']

        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    def create_admin(self, validated_data):
        user = CustomUser(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_no=validated_data['phone_no'],
            user_uuid=validated_data['user_uuid'],
            is_admin=True,
            is_staff=True,
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class AdminSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    email = serializers.EmailField()

    # password1 = serializers.CharField(
    #     write_only=True, style={'input_type': 'password'})

    class Meta:
        model = CustomUser
        fields = ('id', 'user_uuid', 'username', 'first_name', 'last_name', 'role', 'email', 'phone_no', 'is_superuser', 'is_admin',
                  'password')
        lookup_field = 'email'
        write_only_fields = ('password')
        read_only_fields = (
            'id', 'user_uuid', 'is_superuser', 'is_admin'
        )

    @method_decorator(login_required())
    def create_admin(self, validated_data):
        user = CustomUser(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_no=validated_data['phone_no'],
            is_admin=True,

        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class CustomTokenSerializer(TokenObtainSerializer):
   
    def __init__(self, *args, **kwargs):
        self.fields['user_uuid'] = serializers.CharField()
    
    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)
        # print(data)
        # self.user = authenticate(**authenticate_kwargs)
        try:
            self.user = CustomUser.objects.get(user_uuid=data['user_uuid'])
        except ObjectDoesNotExist:
            return 'User with provided UUID does not exist !!!'
        print(self.user) # --> None
        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        print(data)
        return data

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        token['role'] = user.role
        return str(token.access_token)


class EditUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    email = serializers.EmailField()

    class Meta:
        model = CustomUser
        fields = (
            'id','username', 'first_name', 'last_name', 'email', 'phone_no',
            'is_superuser', 'is_admin'
        )
        lookup_field = 'email'
        # write_only_fields = ('password')
        read_only_fields = (
            'id', 'is_superuser', 'is_admin'
        )


class ReadUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = (
        'id', 'username', 'first_name', 'last_name', 'role', 'email', 'phone_no',
        'is_superuser', 'is_admin')
        lookup_field = 'email'
        read_only_fields = (
        'id', 'username', 'first_name', 'last_name', 'role', 'email', 'phone_no',
        'is_superuser', 'is_admin')

