from django.urls import path
from rest_framework_jwt import views
from day6 import views as emp_views

urlpatterns = [
    # 通过jwt获取token
    # path("login/", views.ObtainJSONWebToken.as_view()),
    path("login/", views.obtain_jwt_token),
    path("employee/", emp_views.EmployeeAPIVIew.as_view()),
    path("user_login/", emp_views.LoginAPIView.as_view()),
]
