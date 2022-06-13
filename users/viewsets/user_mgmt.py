import logging

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.filters import SearchFilter
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from users.models import ROLES, CustomUser
from users.permissions import IsSuperUser
from users.serializers import EditUserSerializer, ReadUserSerializer, UserSerializer


@api_view(("GET",))
@permission_classes([permissions.AllowAny])
def get_profile(request):
    user = get_user_model().objects.get(id=request.user.id)
    subject = "Test1"
    message = "This is to test the notification is regenerated."
    # notification = create_notification(title=subject, body=message, label="Test label")
    # Notification.objects.create(title=subject, body=message,user=user, label="Test label")
    print("this is executed")
    user = ReadUserSerializer(user)

    return Response(user.data, status=200)


@method_decorator(name="list", decorator=swagger_auto_schema(tags=["Admin List"]))
@method_decorator(name="update", decorator=swagger_auto_schema(tags=["Admin List"]))
@method_decorator(name="retrieve", decorator=swagger_auto_schema(tags=["Admin List"]))
@method_decorator(name="partial_update", decorator=swagger_auto_schema(tags=["Admin List"]))
class AdminViewSet(
    viewsets.GenericViewSet,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    mixins.DestroyModelMixin,
):
    permission_classes = (permissions.IsAdminUser,)
    queryset = get_user_model().objects.filter(is_admin=True)
    filter_backends = [
        SearchFilter,
    ]
    search_fields = ["email", "first_name", "last_name"]

    def get_serializer_class(self):
        if self.action == "create":
            return UserSerializer
        return EditUserSerializer

    def update(self, request, *args, **kwargs):
        serializer = EditUserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
            except IntegrityError:
                user_email = serializer.data["email"]
                return Response({"message": f"User with email {user_email} already exists"})
            return Response(serializer.data, status=200)
        else:
            return Response(serializer.errors, status=200)

    @action(methods=["POST"], detail=True, url_path="change-password")
    def change_password(self, request, pk):
        user = get_user_model().objects.get(id=pk)
        if not user.check_password(request.data.get("old_password")):
            return Response(
                {"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST
            )
        new_password = request.data.get("new_password")
        if len(new_password) < 8:
            return Response({"message": "Password Too Short"}, status=status.HTTP_400_BAD_REQUEST)
        elif new_password == user.email:
            return Response(
                {"message": "Password Matches Email Try another"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            user.set_password(request.data.get("new_password"))
            user.save()
            return Response({"message": "Password updated successfully"}, 200)

    def create(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.create_admin(serializer.validated_data)
            except IntegrityError:
                user_email = serializer.data["email"]
                user_ph = serializer.data["phone_no"]
                if get_user_model().objects.filter(email=user_email).exists():
                    return Response(
                        {"message": f"User with {user_email} Email already Exists"}, status=200
                    )
                return Response(
                    {"message": f"User with {user_ph} Phone Number already Exists"}, status=200
                )
            user = UserSerializer(user)
            # logger.info(user.data)
            # logger.info(user.data["id"])
            # logger.info(EmailAddress.objects.all())
            id = user.data["id"]
            u = get_user_model().objects.get(id=id)
            # EmailAddress.objects.create(user=u,email=u.email,verified=True,primary=True)
            return Response(user.data, status=200)
        else:
            return Response(serializer.errors, status=200)

    def destroy(self, request, *args, **kwargs):
        try:
            user = request.user.email
            deleted_user = self.get_object().email
            if self.get_object().id == request.user.id:
                return Response(
                    {"message": "Cant Delete yourself "}, status=status.HTTP_400_BAD_REQUEST
                )
            self.perform_destroy(self.get_object())
            # logger.warning(f"{user} Deleted {deleted_user}")
            return Response({"message": "Admin Deleted"}, status=status.HTTP_204_NO_CONTENT)
        except:
            return Response(
                {"message": "Admin Already Deleted"}, status=status.HTTP_204_NO_CONTENT
            )


@method_decorator(name="post", decorator=swagger_auto_schema(tags=["Admin Actions"]))
class PromoteToAdminAPI(APIView):
    permission_classes = (IsSuperUser,)

    def post(self, request, *args, **kwargs):
        uid = request.data.get("user_uuid")
        if not uid:
            return Response({"message": "UID not provided"})
        try:
            user = get_user_model().objects.get(user_uuid=uid)
            if user.is_staff and user.is_admin:
                return Response(
                    {"Message": f"{user.email} is already Promoted to admin"}, status=200
                )
            user.is_staff = True
            user.is_admin = True
            user.save()
            return Response({"Message": f"{user.email} is Promoted to admin"}, status=200)
        except ObjectDoesNotExist:
            return Response({"message": "User Does not exists"}, status=200)


@method_decorator(name="post", decorator=swagger_auto_schema(tags=["Admin Actions"]))
class DemoteToNormalUserAPI(APIView):
    permission_classes = (IsSuperUser,)

    def post(self, request, *args, **kwargs):
        uid = request.data.get("user_uuid")
        if not uid:
            return Response({"message": "UID not provided"})
        try:
            user = get_user_model().objects.get(user_uuid=uid)
            if user.is_superuser:
                return Response({"message": "Cannot demote a superuser"})
            if not user.is_staff and not user.is_admin:
                return Response({"Message": f"{user.email} is not an admin"}, status=200)
            user.is_staff = False
            user.is_admin = False
            user.save()
            return Response({"Message": f"{user.email} is demoted to normal user"}, status=200)
        except ObjectDoesNotExist:
            return Response({"message": "User Does not exists"}, status=200)


@method_decorator(name="list", decorator=swagger_auto_schema(tags=["Users List"]))
@method_decorator(name="update", decorator=swagger_auto_schema(tags=["Users List"]))
@method_decorator(name="retrieve", decorator=swagger_auto_schema(tags=["Users List"]))
@method_decorator(name="partial_update", decorator=swagger_auto_schema(tags=["Users List"]))
class UserView(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """List all users"""

    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes_by_action = {"list": [IsAdminUser]}
    permission_classes = (AllowAny,)
    # pagination_class = CustomPageNumberPagination
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_fields = ["is_admin"]
    search_fields = [
        "email",
        "first_name",
        "last_name",
    ]

    def get_permissions(self):
        try:
            return [permission() for permission in self.permission_classes_by_action[self.action]]
        except KeyError:
            return [permission() for permission in self.permission_classes]


@method_decorator(name="list", decorator=swagger_auto_schema(tags=["Admin Actions"]))
class ListAdminView(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """list all admins"""

    model = CustomUser
    queryset = CustomUser.objects.filter(is_admin=True)
    serializer_class = UserSerializer
    permission_classes_by_action = {
        "list": [IsAdminUser],
    }
    # pagination_class = CustomPageNumberPagination

    def get_permissions(self):
        try:
            # return permission_classes depending on `action`
            return [permission() for permission in self.permission_classes_by_action[self.action]]
        except KeyError:
            # action is not set return default permission_classes
            return [permission() for permission in self.permission_classes]


@method_decorator(name="post", decorator=swagger_auto_schema(tags=["Admin Actions"]))
class ChangeRoleAPI(APIView):
    """
    {
        "user":3,
        "role":"User"
    }
    """

    permission_classes = (IsAdminUser,)

    def post(self, request):
        user = request.data["user"]
        role = request.data["role"]
        if (role, role) not in ROLES:
            return Response({"message": "Invalid Role"})
        try:
            user = get_user_model().objects.get(id=user)
        except ObjectDoesNotExist:
            return Response({"message": "User Doesnt exists"})

        if user.is_superuser:
            return Response({"message": "Cannot change a superuser"})

        if role == "User":
            user.is_admin = False
            user.is_staff = False
            user.is_superuser = False
            user.role = role
            user.save()
        elif role == "Superadmin":
            user.is_admin = True
            user.is_staff = True
            user.is_superuser = True
            user.role = role
            user.save()
        else:
            user.is_admin = True
            user.is_staff = True
            user.is_superuser = False
            user.role = role
            user.save()

        subject = f"Role Changed"
        message = f"Your Role is changed to {role}"
        html_content = render_to_string("account/role_changed.html", {"user": user, "role": role})
        to_mail = [user.email]
        # send_email.delay(subject,message,html_content,to_mail,from_mail="system@mail.akku.gg")
        # Notification.objects.create(title="Role Changed", body=message, user=user, label="System")

        return Response({"message": f"Successfully Changed to {role}"})


@method_decorator(name="list", decorator=swagger_auto_schema(tags=["Admin Actions"]))
class UserListView(ListAPIView):
    """List all users"""

    queryset = CustomUser.objects.all()
    serializer_class = ReadUserSerializer
    permission_classes = (IsAdminUser,)
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_fields = ["is_admin"]
    search_fields = [
        "email",
        "first_name",
        "last_name",
    ]
