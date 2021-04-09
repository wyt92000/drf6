from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_jwt.authentication import JSONWebTokenAuthentication

from day6.jwt_authentication import JWTAuthentication
from day6.serializer import UserModelSerializer


class EmployeeAPIVIew(APIView):
    """只有登录的用户才可以访问"""
    # 登录用户才可以访问
    permission_classes = [IsAuthenticated]
    # 解析访问此视图请求中携带的 jwt token
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        """获取所有员工信息"""
        return Response("所有员工数据")


class LoginAPIView(APIView):
    """
    实现在多条件登录的情况下完成token的签发
    1. 禁用权限与认证组件
    2. 获取前端传递的参数
    3. 校验参数，得到合法的用户
    4. 签发token并返回
    """

    authentication_classes = ()
    permission_classes = ()

    def post(self, request, *args, **kwargs):
        """
        接收登录请求，校验用户的登录信息是否合法
        :return:  登录成功则返回用户 与 token
        """
        request_data = request.data

        serializer = UserModelSerializer(data=request_data)
        serializer.is_valid(raise_exception=True)
        # serializer.data 序列化器中定义的参与序列化的字段
        return Response({
            "token": serializer.token,
            "user": UserModelSerializer(serializer.user).data})
