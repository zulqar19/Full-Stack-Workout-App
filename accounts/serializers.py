from rest_framework import serializers
from . models import User
from .utils import Util
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode , urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class UserRegistrationSerializers(serializers.ModelSerializer):

    # We are writing password2 becoz we need Confirm Password field in our registration
    password2 = serializers.CharField(style = {'input_type' : 'password'} , write_only = True)

 
    class Meta:
        model = User
        fields = ['email' , 'name', 'tc' , 'password' , 'password2']
        extra_kwargs = {
            'password' : {'write_only' : True},
            'password2' : {'write_only' : True}

        }

    def validate(self , data):
        password = data.get('password')
        password2 = data.get('password2')

        if password != password2:
            raise serializers.ValidationError("password and confirm password doesn't match")
        return data
    
    def create(self , validate_data):
        return User.objects.create_user(**validate_data)
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 255)
    class Meta:
        model = User
        fields = ["email" , "password"]


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id" , "email" , "name"]

class UserChangePasswordSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style = {'input_type' : 'password'} , write_only = True)

    class Meta:
        model = User
        fields = ["password" , "password2"]

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("password and confirm password doesn't match")
        user.set_password(password)
        user.save()
        return data
        
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 255)

    class meta:
        fields = ['email']

    def validate(self, data):
        email = data.get('email')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = "http://localhost/3000/api/user/reset/"+uid+"/"+token
            print(link)
            #Send Email
            data={
                "subject" : "Reset your Password",
                "body" : "click the link to reset your password " + link,
                "to_email" : user.email 
            }
            Util.send_email(data)
            return data
        else:
            raise serializers.ValidationError("users doesn't exists!")
        return data

class ResetPasswordSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style = {'input_type' : 'password'} , write_only = True)

    class Meta:
        model = User
        fields = ["password" , "password2"]

    def validate(self, data):
        try:
            password = data.get('password')
            password2 = data.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("password and confirm password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user , token):
                raise serializers.ValidationError("Token is not valid or expired")
            user.set_password(password)
            user.save()
            return data
        except DjangoUnicodeDecodeError:
            PasswordResetTokenGenerator().check_token(user , token)
            raise serializers.ValidationError("Token is not valid or expired")
