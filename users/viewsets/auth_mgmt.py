# from allauth.account.admin import EmailAddress
from datetime import datetime

import jwt
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.utils.decorators import method_decorator
from drf_yasg.utils import swagger_auto_schema
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.utils import *
from rest_framework_simplejwt.views import TokenObtainPairView
from users.models import CustomUser
from users.serializers import MyTokenObtainPairSerializer, ReadUserSerializer, UserSerializer

# from rest_framework_jwt.authentication import JSONWebTokenAuthentication

@method_decorator(name="post", decorator=swagger_auto_schema(tags=["AuthManagement"]))
class RegisterUserView(CreateAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            if get_user_model().objects.filter(phone_no=request.data.get("phone_no")).exists():
                return Response({"message": "User with phone number exists"}, status=400)
            user = serializer.create(serializer.validated_data)
            data = ReadUserSerializer(user).data
            return Response({"user": data}, status=200)

        else:
            return Response(serializer.errors, status=200)


@method_decorator(name="post", decorator=swagger_auto_schema(tags=["AuthManagement"]))
class LoginAPI(TokenObtainPairView):
    permission_class = (AllowAny,)

    def post(self, request, *args, **kwargs):
        uuid = request.data.get("user_uuid")
        if not uuid:
            return Response({"message": "UUID not provided"}, status=400)
        try:
            user = get_user_model().objects.get(user_uuid=uuid)
            data = MyTokenObtainPairSerializer.get_token(user=user)
            return Response({"token": data}, status=200)

        except ObjectDoesNotExist:
            return Response({"message": "User Does not exists"}, status=400)

@method_decorator(name="post", decorator=swagger_auto_schema(tags=["AuthManagement"]))
class VerifyTokenViewSet(APIView):
    permission_class = (AllowAny,)
    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({"No token Provided"}, status=401)
        decoded_data = jwt.decode(token,None,None)
        exp = datetime.fromtimestamp(decoded_data['exp'])
        if exp<datetime.now():
            return Response({'Token has already expired. Please login again!'}, status=401)
        if 'username' in decoded_data:
            try:
                CustomUser.objects.get(username=decoded_data['username'])
            except ObjectDoesNotExist:
                return Response({"User with given uuid does not exist."}, status=401)
        else:
            return Response('Invalid Token!')
        return Response(decoded_data, status=200)
