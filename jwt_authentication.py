import jwt
from rest_framework import exceptions
from rest_framework_jwt.authentication import BaseJSONWebTokenAuthentication

from rest_framework_jwt.settings import api_settings

jwt_decode_handler = api_settings.JWT_DECODE_HANDLER


class JWTAuthentication(BaseJSONWebTokenAuthentication):

    def authenticate(self, request):

        # 获取前端请求中所携带的token
        jwt_value = request.META.get("HTTP_AUTHORIZATION")

        if jwt_value is None:
            return None

        # 自定义校验规则
        token = self.parse_jwt_token(jwt_value)

        try:
            # 通过token解析出载荷
            payload = jwt_decode_handler(token)
        except jwt.ExpiredSignature:
            raise exceptions.AuthenticationFailed('签名已过期')
        except jwt.DecodeError:
            raise exceptions.AuthenticationFailed("签名不合法")
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        # 如果解析过程中没有任何错误，则将通过载荷得到用户
        user = self.authenticate_credentials(payload)

        return user, token

    def parse_jwt_token(self, jwt_value):
        """解析jwt token"""
        tokens = jwt_value.split()
        if len(tokens) != 3 or tokens[0].lower() != "auth" or tokens[2].lower() != "jwt":
            return None

        # 如果格式合法，则返回token本身
        return tokens[1]
