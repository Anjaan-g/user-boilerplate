import os
import uuid

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.db.models.fields import CharField
from django.db.models.signals import post_delete, post_save
from django.utils import timezone
try:
    from django.utils.translation import ugettext_lazy as _
except ImportError:
    from django.utils.translation import gettext_lazy as _
    
from .managers import CustomUserManager

"""Model for custom user """
ROLES = (("Superadmin", "Superadmin"), ("Admin", "Admin"), ("User", "User"))


class CustomUser(AbstractBaseUser, PermissionsMixin):
    user_uuid = models.CharField(max_length=255, unique=True)
    username = models.CharField(_("username"), db_index=True, unique=True, max_length=50)
    email = models.EmailField(unique=True,  null=True, blank=True)
    phone_no = models.CharField(max_length=50, null=True, unique=True, blank=True)
    first_name = models.CharField(max_length=120, blank=True)
    last_name = models.CharField(max_length=120, blank=True)

    is_admin = models.BooleanField("admin", default=False)
    role = models.CharField(max_length=40, choices=ROLES, default="User", blank=True)
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = "username"

    ordering = ("created",)

    def get_full_name(self):
        if self.first_name and self.last_name:
            return self.first_name + " " + self.last_name
        else:
            return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    def __str__(self):
        if self.email:
            return f"{self.email}"
        else:
            return f"{self.phone_no}"
