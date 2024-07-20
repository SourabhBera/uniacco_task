from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, OTP
from .serializers import UserSerializer, OTPRequestSerializer, OTPSerializer
from django.utils.crypto import get_random_string
from django.utils import timezone
from datetime import timedelta

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user, created = User.objects.get_or_create(email=email)
            if created:
                return Response({'message': 'Registration successful. Please verify your email.'}, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'Email already registered.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RequestOTPView(APIView):
    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                otp = get_random_string(length=6, allowed_chars='0123456789')
                OTP.objects.create(user=user, otp=otp)
                # Mock email service: Print OTP to console
                print(f"OTP for {email}: {otp}")
                return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'message': 'Email not registered.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            try:
                user = User.objects.get(email=email)
                otp_instance = OTP.objects.filter(user=user, otp=otp, is_verified=False, created_at__gte=timezone.now() - timedelta(minutes=10)).first()
                if otp_instance:
                    otp_instance.is_verified = True
                    otp_instance.save()
                    refresh = RefreshToken.for_user(user)
                    return Response({'message': 'Login successful.', 'token': str(refresh.access_token)}, status=status.HTTP_200_OK)
                else:
                    return Response({'message': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({'message': 'Email not registered.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
