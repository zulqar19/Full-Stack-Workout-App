from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view , renderer_classes , permission_classes
from . models import User
from . serializers import UserRegistrationSerializers, UserLoginSerializer, UserProfileSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, ResetPasswordSerializer
from . renderers import UserRenderer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }


# Create your views here.
@api_view(['POST'])
@renderer_classes([UserRenderer])
def UserRegistrationView(request):
    if request.method == 'POST':
        serializer = UserRegistrationSerializers(data = request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)        
            res = {'msg' : 'User created' ,  "token" : token}
            return Response(res , status= status.HTTP_201_CREATED)
        return Response(serializer._errors , status= status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@renderer_classes([UserRenderer])
def UserLoginView(request):
    if request.method == 'POST':
        serializer = UserLoginSerializer(data = request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email = email , password = password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({"msg" : "Login Successful" , "token" : token} , status= status.HTTP_200_OK)
            else: 
                return Response({"errors" : {"non_field_error" : ['Email or password is not valid']}})

        return Response(serializer.errors , status= status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET'])
@renderer_classes([UserRenderer]) 
@permission_classes([IsAuthenticated])
def UserProfileView(request):
    if request.method == 'GET':
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data , status= status.HTTP_200_OK)   
    
@api_view(['POST'])
@renderer_classes([UserRenderer]) 
@permission_classes([IsAuthenticated])
def UserChangePasswordView(request):
    if request.method == "POST":
        serializer = UserChangePasswordSerializer(data = request.data , context ={"user" : request.user} )
        if serializer.is_valid(raise_exception=True):
            return Response({"msg" : "password Changed Succesfully"} , status= status.HTTP_200_OK)
        return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@renderer_classes([UserRenderer]) 
def SendPasswordResetEmailView(request):
    if request.method == "POST":
        serializer = SendPasswordResetEmailSerializer(data = request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({"msg" : "link has been sent to Email for reset password"}, status = status.HTTP_200_OK )
        return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@renderer_classes([UserRenderer]) 
def ResetPasswordView(request , uid , token):
    if request.method == "POST":
        serializer = ResetPasswordSerializer(data=request.data , context = {"uid" : uid , "token" : token})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg" : "password reset successfully"} , status=status.HTTP_200_OK)
        return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@renderer_classes([UserRenderer])
@permission_classes([IsAuthenticated])
def UserLogoutView(request):
    if request.method == 'POST':
        try:
            refresh_token = request.data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"msg": "Logged out"}, status=status.HTTP_205_RESET_CONTENT)
        except:
            return Response({"msg": "Error Occurred"}, status=status.HTTP_400_BAD_REQUEST)

