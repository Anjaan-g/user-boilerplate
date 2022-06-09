import random

from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _


class CustomUserManager(BaseUserManager):
    """
    Custom User Manager to create user, superuser and admin. Takes username as default identifier for all users
    """

    use_in_migrations = True

    def create_user(self, username, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not username:
            raise ValueError(_("The Username must be set"))
        # username = self.normalize_email(email)
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        extra_fields.setdefault("role", "User")
        # alpha_num = 'abcdefghijklmnopqrstuvwxyz12345567890'
        user.save()
        return user

    def create_superuser(self, username, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("role", "Superadmin")
        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        if extra_fields.get("is_admin") is not True:
            raise ValueError(_("Superuser must have is_admin=True."))
        return self.create_user(username, password, **extra_fields)

    def create_admin(self, username, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("role", "Admin")
        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Admin must have is_staff=True."))
        if extra_fields.get("is_admin") is not True:
            raise ValueError(_("Admin must have is_admin=True."))
        return self.create_user(username, password, **extra_fields)
