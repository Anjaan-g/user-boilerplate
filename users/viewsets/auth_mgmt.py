# from allauth.account.admin import EmailAddress
from datetime import datetime

import jwt
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.utils.decorators import method_decorator
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
            # EmailAddress.objects.create(user=user,email=user.email,verified=True,primary=True)
            # jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            # jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
            # payload = jwt_payload_handler(user)
            # if api_settings.JWT_ALLOW_REFRESH:
            #     payload["orig_iat"] = timegm(datetime.utcnow().utctimetuple())
            data = ReadUserSerializer(user).data
            return Response({"user": data}, status=200)

        else:
            return Response(serializer.errors, status=200)


# @method_decorator(name='post',decorator=swagger_auto_schema(tags=['AuthManagement']))
class LoginAPI(TokenObtainPairView):
    permission_class = (AllowAny,)

    def post(self, request, *args, **kwargs):
        uuid = request.data.get("user_uuid")
        if not uuid:
            return Response({"message": "UUID not provided"}, status=400)
        try:
            user = get_user_model().objects.get(user_uuid=uuid)
            print(user)
            data = MyTokenObtainPairSerializer.get_token(user=user)
            return Response({"token": data}, status=200)

        except ObjectDoesNotExist:
            return Response({"message": "User Does not exists"}, status=400)


class VerifyTokenViewSet(APIView):
    permission_class = (AllowAny,)

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"No token Provided"}, status=401)
        decoded_data = jwt.decode(token, None, None)
        exp = datetime.fromtimestamp(decoded_data["exp"])
        if exp < datetime.now():
            return Response({"Token has already expired. Please login again!"}, status=401)
        # print(decoded_data.data)
        # user_uuid = decoded_data.user_uuid
        if "user_uuid" in decoded_data:
            try:
                CustomUser.objects.get(user_uuid=decoded_data["user_uuid"])
            except ObjectDoesNotExist:
                return Response({"User with given uuid does not exist."}, status=401)
        else:
            return Response("Invalid Token!")
        return Response(decoded_data, status=200)
