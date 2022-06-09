from django.urls import include, path

from users.viewsets.auth_mgmt import (LoginAPI, RegisterUserView,
                                        VerifyTokenViewSet)
# from account.viewsets.SettingManagement import SiteSettingsAPI,SEOSettingsAPI
from users.viewsets.user_mgmt import (ChangeRoleAPI,
                                           DemoteToNormalUserAPI,
                                           PromoteToAdminAPI, UserListView,
                                           get_profile)

from .routers import router

app_name = 'users'

urlpatterns = [
    path('', include(router.urls)),
    path('get-profile/', get_profile, name='get_profile'),
    path('register/', RegisterUserView.as_view(), name='register'), #Only to create user
    path('login/',LoginAPI.as_view(), name='login'),
    path('token-verify/', VerifyTokenViewSet.as_view(), name='token_verify'),


    # path('promote-to-admin/',PromoteToAdminAPI.as_view(), name='promote_to_admin'),
    # path('demote-to-normal-user/',DemoteToNormalUserAPI.as_view(), name='demote_to_normal_user'),
    
    # path('change-role/',ChangeRoleAPI.as_view(),name='change_role'),
    path('user-list-all/',UserListView.as_view(),name='user_list_all'),
]