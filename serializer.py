import re

from rest_framework.serializers import ModelSerializer
from rest_framework import serializers, exceptions
from rest_framework_jwt.settings import api_settings

from api.models import User

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


class UserModelSerializer(ModelSerializer):
    # 自定义字段  不需要与模型中字段进行映射  只是为了序列化器能接收到这个字段
    account = serializers.CharField(write_only=True)
    pwd = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["account", "pwd", "username", "phone"]

        # 在此参数定义的字段需要与模型映射
        extra_kwargs = {
            "username": {
                "read_only": True
            },
            "phone": {
                "read_only": True
            },
        }

    def validate(self, attrs):
        account = attrs.get("account")
        pwd = attrs.get("pwd")

        # 对于前端提供的用户信息进行校验
        if re.match(r'.+@.+', account):
            # 邮箱登录
            user = User.objects.filter(email=account).first()
        elif re.match(r'1[3-9][0-9]{9}', account):
            # 手机号
            user = User.objects.filter(phone=account).first()
        else:
            user = User.objects.filter(username=account).first()

        # 判断用户是否存在 且密码是否正确
        if user and user.check_password(pwd):
            # 通过用户生成载荷  根据载荷签发token
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)
            # 将token通过序列化器返回给视图
            self.token = token
            self.user = user
        else:
            raise exceptions.ValidationError("账号或密错误")

        # django默认密码加密的方式
        # password = make_password("123456")

        return attrs
