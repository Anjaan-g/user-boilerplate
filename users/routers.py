from rest_framework import routers

from users.viewsets.user_mgmt import AdminViewSet, UserView

router = routers.DefaultRouter()

router.register('user', UserView, basename='users')
router.register('admin', AdminViewSet, basename='admin')
