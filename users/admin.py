from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from .forms import CustomUserChangeForm, CustomUserCreationForm
from .models import CustomUser


class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser
    list_display = [
        "username",
        "email",
        "user_uuid",
        "role",
        "first_name",
        "last_name",
        "phone_no",
        "is_active",
        "is_admin",
    ]
    list_filter = ["is_active", "role", "is_admin"]
    list_editable = ("role",)
    ordering = [
        "date_joined",
    ]
    fieldsets = (
        (
            "Required Information",
            {
                "fields": (
                    "user_uuid",
                    "username",
                    "role",
                    "password",
                )
            },
        ),
        (
            "Optional Information",
            {
                "classes": ("collapse",),
                "fields": (
                    ("first_name", "last_name"),
                    ("email", "phone_no"),
                ),
            },
        ),
        (
            "Permissions",
            {"classes": ("collapse",), "fields": ("is_staff", "is_admin", "is_active")},
        ),
        (
            "Important Dates",
            {
                "classes": ("collapse",),
                "fields": ("last_login","date_joined",),
            },
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "email",
                    "phone_no" "first_name",
                    "last_name",
                    "user_uuid",
                    "password1",
                    "password2",
                ),
            },
        ),
    )
    search_fields = ("email", "username", "phone_no", "first_name", "last_name")
    ordering = ("date_joined",)


admin.site.register(CustomUser, CustomUserAdmin)
