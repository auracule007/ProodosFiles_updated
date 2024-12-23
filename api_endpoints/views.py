import base64
from datetime import datetime, timedelta, timezone
import io
import zipfile
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
import hashlib
import os
import re
import shutil
import zipfile
import chardet
from django.conf import settings
from django.urls import reverse
from rest_framework import serializers, generics, views, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, JSONParser, BaseParser

from django.http import FileResponse, Http404, HttpResponseForbidden, JsonResponse
from django.utils.http import urlencode
from django.db import transaction

from django.shortcuts import get_object_or_404, redirect, render
from django.core.validators import RegexValidator
from django.contrib.auth.decorators import login_required
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import login
from cryptography.fernet import Fernet

from django.core.files.storage import default_storage

from file_management.models import File, SharedFile, apply_correct_path
from folder_management.models import Folder, SharedFolder
from user_management.forms import RegistrationForm
from user_management.models import CustomUser

from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator

from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.core.mail import send_mail

from django.template.loader import render_to_string

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.html import strip_tags
from django.utils.encoding import force_bytes, force_str

from user_management.token import account_activation_token

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from drf_spectacular.utils import extend_schema, OpenApiParameter, extend_schema_field, OpenApiExample
from drf_spectacular.types import OpenApiTypes

url = "https://prodosfiles.vercel.app"

def createBasicResponse(status=200, responseText='', data=''):
    return {'status': status, 'responseText': responseText, 'data': data}

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    # Add the URL field with the validator
    # url = serializers.URLField(
    #     required=True
    # )

    # url = "https://proodos-files-ff33.vercel.app/"
    
    
    class Meta:
        model = CustomUser
        fields = ['username', 'full_name', 'email', 'password', 'url']

    @extend_schema_field(OpenApiTypes.STR)
    def get_url_field_schema(self):
        return OpenApiTypes.STR
    
    def validate(self, attrs):
        # Validate username uniqueness
        username = attrs.get('username')
        if CustomUser.objects.filter(username=username).exists():
            raise serializers.ValidationError("This username is already taken.")
        
        # Validate email uniqueness
        email = attrs.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("This email address is already registered.")
        
        return attrs

    def create(self, validated_data):
        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            full_name=validated_data['full_name'],
            is_active=False  # Prevent login until email is verified
        )
        user.set_password(validated_data['password'])
        user.quota = 10 * 1024 * 1024
        user.save()
        self.send_verification(self.context['request'], user, f"{url}/email-verification-success")
        return user

    def send_verification(self, request, user, url):
        current_site = get_current_site(request)
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        print(user.pk, "pk")
        print(token)
        print(uidb64)
        url_tail = str({"token": f"{token}", "u_id": f"{uidb64}"}).encode("ascii")
        mail_subject = 'Activation link'  
        message = render_to_string('acc_active_email.html', {  
            'user': user,  
            'url': url,  
            'uid':urlsafe_base64_encode(url_tail),   
        })
        to_email = user.email
        print(to_email)
        plain_message = strip_tags(message)
        send_mail(mail_subject, plain_message, "verify@codedextersacademy.com", [to_email], html_message=message)
        print("sent")

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    @extend_schema(
            description="API for registering user details. URL field is required for this to work."
    )
    def create(self, request, *args, **kwargs):
        # Call the serializer to create the user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        print(serializer.validated_data)
        # return serializer.validated_data

        # Send success response after registration
        return Response(
            {
                "data": "",
                "responseText": "Registration successful. Please check your email to verify your account.",
                "status": 201
                # "user": {
                #     "username": user.username,
                #     "email": user.email
                # }
            }, 
            status=status.HTTP_201_CREATED
        )
    
    def handle_exception(self, exc):
        # Handle exceptions raised by the serializer
        if isinstance(exc, serializers.ValidationError):
            # Format validation errors as JSON
            # print(exc.detail)
            result = []
            for key in exc.detail:
                for errors in exc.detail[key]:
                    result.append(errors)

            return Response({
                "status": 400,
                "responseText": result
            }, status=status.HTTP_400_BAD_REQUEST)

        # For other exceptions, fallback to default behavior
        return super().handle_exception(exc)

User = get_user_model()

class ResendSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResendVerificationEmailView(views.APIView):
    serializer_class = ResendSerializer
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    @extend_schema(
        description="Resends a verification email if former link has expired",
        summary="",
        responses={
            200: OpenApiExample(
                "Success",
                value={
                    "responseText": "Email sent if user exists"
                }
            )
        }
    )
    def post(self, request):
        email = request.data.get('email')
        
        try:
            # Get the user by email
            user = CustomUser.objects.get(email=email)
            
            # Ensure the user is not already active
            if user.is_active:
                return Response({'responseText': 'This account is already verified.'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Resend the verification email
            RegisterSerializer().send_verification(request, user, f"{url}/email-verification-success")
            return Response({'responseText': 'Email sent if it exists on our server.'}, status=status.HTTP_200_OK)
        
        except CustomUser.DoesNotExist:
            return Response({'responseText': 'Email sent if it exists on our server.'}, status=status.HTTP_200_OK)
    
    def send_verification(self, request, user, url):
        current_site = get_current_site(request)
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Construct the query parameter containing token and uidb64
        u_info = urlsafe_base64_encode(force_bytes({"token": token, "u_id": uidb64}))

        # Build the complete URL with the u_info parameter appended as a query parameter
        verification_url = f"{url}?u_info={u_info}"
        
        mail_subject = 'Activation link'
        message = render_to_string('acc_active_email.html', {
            'user': user,
            'url': verification_url,  # Use the newly constructed URL
        })
        to_email = user.email
        plain_message = strip_tags(message)
        send_mail(mail_subject, plain_message, "verify@codedextersacademy.com", [to_email], html_message=message)

        print(f"Verification email sent to: {to_email}")
        print(f"Verification URL: {verification_url}")


# class ResendVerificationEmailView(views.APIView):
#     serializer_class = ResendSerializer
#     permission_classes = [AllowAny]
#     parser_classes = [JSONParser]

#     @extend_schema(
#         description="Resends a verification email if former link has expired",
#         summary="",
#         responses={
#             200: OpenApiExample(
#                 "Success",
#                 value={
#                     "responseText": "Email sent if user exists"
#                 }
#             )
#         }
#     )
#     def post(self, request):
#         email = request.data.get('email')
        
#         try:
#             # Get the user by email
#             user = CustomUser.objects.get(email=email)
            
#             # Ensure the user is not already active
#             if user.is_active:
#                 return Response({'responseText': 'This account is already verified.'}, status=status.HTTP_400_BAD_REQUEST)
            
#             # Resend the verification email
#             RegisterSerializer().send_verification(request, user, request.data.get('url'))
#             return Response({'responseText': 'Email sent if it exists on our server.'}, status=status.HTTP_200_OK)
        
#         except CustomUser.DoesNotExist:
#             return Response({'responseText': 'Email sent if it exists on our server.'}, status=status.HTTP_400_BAD_REQUEST)
    
#     def send_verification(self, request, user, url):
#         current_site = get_current_site(request)
#         token = default_token_generator.make_token(user)
#         uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
#         print(user.pk, "pk")
#         print(token)
#         print(uidb64)
#         url_tail = str({"token": f"{token}", "u_id": f"{uidb64}"}).encode("ascii")
#         mail_subject = 'Activation link'  
#         message = render_to_string('acc_active_email.html', {  
#             'user': user,  
#             'url': url,  
#             'uid':urlsafe_base64_encode(url_tail),   
#         })
#         to_email = user.email
#         print(to_email)
#         plain_message = strip_tags(message)
#         send_mail(mail_subject, plain_message, "verify@codedextersacademy.com", [to_email], html_message=message)
#         print("sent")


class VerifyEmailSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        uidb64 = data.get('uidb64')
        token = data.get('token')
        print(uidb64)
        print(token)
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            raise serializers.ValidationError("Invalid user or UID")
        print(default_token_generator.check_token(user, token))
        if default_token_generator.check_token(user, token):
            return user
        raise serializers.ValidationError("Invalid token or expired")
        
class VerifyEmailView(views.APIView):
    serializer_class = VerifyEmailSerializer
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]
    
    @extend_schema(
        description="API for verifying email. uidb64 and token are to be passed as payload."
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        print(request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            user.is_active = True
            user.quota = 15 * 1024 * 1024 * 1024
            user.save()
            return Response({'responseText': 'Email verified successfully', 'status': 200}, status=status.HTTP_200_OK)
        return Response({'responseText': 'Invalid or expired verification link', 'status': 400}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema_field(serializers.CharField)
def get_url_schema():
    return OpenApiExample(
        "Example URL",
        value="https://www.example.com",
        description="Please provide a valid URL."
    )
    

def authenticates(email=None, password=None, **kwargs):
    UserModel = get_user_model()
    try:
        user = UserModel.objects.get(email=email)
    except UserModel.DoesNotExist:
        return None
    else:
        if user.check_password(password):
            return user
    return None

class PlainTextParser(BaseParser):
    """
    Plain text parser for handling text/plain requests.
    """
    media_type = 'text/plain'

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Simply return a string from the incoming request.
        """
        return stream.read().decode('utf-8')


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('email')
        password = data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            return user
        raise serializers.ValidationError(f"Invalid credentials or account not activated.")

class LoginView(APIView):
    serializer_class = LoginSerializer
    parser_classes = [JSONParser]  # Specify the serializer class
    
    @extend_schema(
        description="API for login. Sends back a token to be saved on browser."
    )
    def post(self, request, *args, **kwargs):
        # request['Referrer-Policy'] = 'no-referrer'
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            # if Token.objects.filter(user=user).exists():
            #     Token.objects.get(user=user).delete()
            token, created = Token.objects.get_or_create(user=user)
            response = {'token': token.key, 'username': user.username, 'full_name': user.full_name, "email": user.email}
            print(response)
            return Response(response, status=200)
        response = {'responseText': []}
        for key in serializer.errors.keys():
            for err in serializer.errors[key]:
                response['responseText'].append(err)
        return Response(response, status=400)

# class LoginSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     password = serializers.CharField()

#     def validate(self, data):
#         user = authenticate(username=data.get('email'), password=data.get('password'))
#         if user:
#             return user
#         raise serializers.ValidationError("Invalid credentials or account not activated.")

# class LoginView(APIView):
#     serializer_class = LoginSerializer
#     parser_classes = [JSONParser]

#     @extend_schema(description="API for login. Sends back a token to be saved on browser.")
#     def post(self, request, *args, **kwargs):
#         serializer = self.serializer_class(data=request.data)
#         if serializer.is_valid():
#             user = serializer.validated_data

#             # Caching the token
#             cache_key = f"user_token_{user.id}"
#             token_key = cache.get(cache_key)
            
#             if not token_key:
#                 # If token not in cache, update or create and store in cache
#                 token, _ = Token.objects.update_or_create(user=user, defaults={'key': Token.generate_key()})
#                 cache.set(cache_key, token.key, timeout=3600)  # Cache for 1 hour
#             else:
#                 # Fetch token from the database if cached key exists
#                 token = Token.objects.get(key=token_key)

#             # Construct the response payload
#             response = {
#                 'token': token.key,
#                 'username': user.username,
#                 'full_name': getattr(user, 'full_name', None),
#                 'email': user.email
#             }
#             return Response(response, status=200)

#         # Collect error messages efficiently
#         response = {
#             'responseText': [err for errors in serializer.errors.values() for err in errors]
#         }
#         return Response(response, status=400)


class FileUploadSerializer(serializers.Serializer):
    files = serializers.ListField(
        child=serializers.FileField(),
        allow_empty=False
    )
    folder_id = serializers.UUIDField(required=False)
    override = serializers.BooleanField(default=False)

    def validate(self, data):
        if data.get('folder_id'):
            if Folder.objects.filter(id=data.get('folder_id')).exists():
                return data
            return serializers.ValidationError("Folder does not exist")
        return data
    
    # class Meta:
    #     model = File
    #     fields = ['id', 'name', 'file', 'size']
    #     read_only_fields = ['id', 'name', 'size']

    # def create(self, validated_data):
    #     request = self.context.get('request')
    #     folder = self.context.get('folder')
    #     file_instance = File(
    #         name=validated_data['file'].name,
    #         owner=request.user,
    #         parent=folder,
    #         file=validated_data['file'],
    #         size=validated_data['file'].size
    #     )
    #     return file_instance.save(override=self.context.get('override', False))  

@extend_schema(
    request=FileUploadSerializer,
    responses={201: {"status": 201, "responseText": "Files have been uploaded successfully"}, 403: {"status": 201, "responseText": "This action cannot be performed"}},
    description="Upload multiple files to a folder"
)
class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    # def post(self, request):
    #     serializer = FileUploadSerializer(data=request.data)
    #     if serializer.is_valid():
    #         folder_id = serializer.validated_data.get('folder_id')
    #         if folder_id:
    #             folder = get_object_or_404(Folder, id=folder_id)
    #             if not folder.is_editor(request.user.id):
    #                 if folder.has_perm(request.user.id):
    #                     return Response({"responseText": "You do not have permission to upload"}, status=status.HTTP_403_FORBIDDEN)
    #                 return Response({"responseText": "This action cannot be performed"}, status=status.HTTP_403_NOT_FOUND)
    #         else:
    #             folder = None
    
    #         files = serializer.validated_data['files']
    #         override = serializer.validated_data['override']
    
    #         with transaction.atomic():
    #             for uploaded_file in files:
    #                 file_instance = File(
    #                     name=os.path.basename(uploaded_file.name),
    #                     owner=request.user,
    #                     parent=folder,
    #                     file=uploaded_file,
    #                     size=uploaded_file.size
    #                 )
    #                 file_instance.save(override=override)
    
    #                 if folder:
    #                     if folder.owner != request.user:
    #                         shared_folder_qs = SharedFolder.objects.filter(folder=folder, shared_by=request.user)
    #                         for sharing in shared_folder_qs:
    #                             SharedFile.objects.get_or_create(
    #                                 user=sharing.user,
    #                                 file=file_instance,
    #                                 shared_by=request.user,
    #                                 role=sharing.role
    #                             )
    #                         SharedFile.objects.get_or_create(
    #                             user=folder.owner,
    #                             file=file_instance,
    #                             shared_by=request.user,
    #                             role=3
    #                         )
    
    #         return Response({"responseText": "Files have been uploaded successfully"}, status=status.HTTP_201_CREATED)
    #     response = {'responseText': []}
    #     for key in serializer.errors.keys():
    #         for err in serializer.errors[key]:
    #             response['responseText'].append(err)
    #     return Response(response, status=status.HTTP_400_BAD_REQUEST)
    

    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        if serializer.is_valid():
            folder_id = serializer.validated_data.get('folder_id')
            if folder_id:
                folder = get_object_or_404(Folder, id=folder_id)
                if not folder.is_editor(request.user.id):
                    if folder.has_perm(request.user.id):
                        return Response({"responseText": "You do not have permission to upload"}, status=status.HTTP_403_FORBIDDEN)
                    return Response({"responseText": "This action cannot be performed"}, status=status.HTTP_403_NOT_FOUND)

            else:
                folder = None
            
        
            files = serializer.validated_data['files']
            override = serializer.validated_data['override']
            print("doing something..")

            for uploaded_file in files:
                file_instance = File(
                    name=os.path.basename(uploaded_file.name),
                    owner=request.user,
                    parent=folder,
                    file=uploaded_file,
                    size=uploaded_file.size
                )
                file_instance.save(override=override)

                if folder:
                    if folder.owner != request.user:
                        if SharedFolder.objects.filter(folder=folder, shared_by=request.user).exists():
                            for sharing in SharedFolder.objects.filter(folder=folder, shared_by=request.user):
                                SharedFile.objects.get_or_create(
                                    user=sharing.user, 
                                    file=file_instance, 
                                    shared_by=request.user, 
                                    role=sharing.role
                                )
                        SharedFile.objects.get_or_create(
                            user=folder.owner, 
                            file=file_instance, 
                            shared_by=request.user, 
                            role=3
                        )

            return Response({"responseText": "Files have been uploaded successfully"}, status=status.HTTP_201_CREATED)
        response = {'responseText': []}
        for key in serializer.errors.keys():
            for err in serializer.errors[key]:
                response['responseText'].append(err)
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        # Ensure the email exists in the user model
        User = get_user_model()
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is not registered.")
        return value

@extend_schema(
    request=PasswordResetRequestSerializer,
    description="API for sending the verification email. URL field."
)
class PasswordResetRequestAPIView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)

        if serializer.is_valid():
            User = get_user_model()
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            # Generate token and uidb64
            token = PasswordResetTokenGenerator().make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

            # Get the domain of the current site (needed for email)
            url = f"https://prodosfiles.vercel.app/reset-password/"
            self.send_reset(request, user, url, token, uidb64)
            return Response({'responseText': "Email sent successfully"})
        response = {'responseText': []}
        for key in serializer.errors.keys():
            for err in serializer.errors[key]:
                response['responseText'].append(err)
        return Response(response, status=400)


    def send_reset(self, request, user, url, token, uidb64):
        url_tail = str({"token": f"{token}", "u_id": f"{uidb64}"}).encode("ascii")
        mail_subject = 'Activation link'  
        message = render_to_string('password_reset_email.html', {  
            'user': user,  
            'url': url,  
            'uid':urlsafe_base64_encode(url_tail),   
        })
        to_email = user.email
        plain_message = strip_tags(message)
        send_mail(mail_subject, plain_message, "verify@codedextersacademy.com", [to_email], html_message=message)

# class FolderCreateSerializer(serializers.Serializer):
#     folder_name = serializers.CharField(max_length=255, required=True)
#     parent_folder_id = serializers.UUIDField(required=False)  # Optional, in case it's a nested folder

#     # Made change
#     def validate_folder_name(self, value):
#         if not value:
#             raise serializers.ValidationError("Folder name cannot be empty.")

#         parent_folder_id = self.initial_data.get('parent_folder_id')  # Correct way to access the parent folder ID
#         if parent_folder_id:
#             try:
#                 parent_f = Folder.objects.get(id=self.parent)
#                 if Folder.objects.filter(name=value, parent=parent_f).exists():
#                     raise serializers.ValidationError("Folder with that name already exists")
#             except Folder.DoesNotExist:
#                 raise serializers.ValidationError("The Parent folder does not exist")

#         return value

class FolderCreateSerializer(serializers.Serializer):
    folder_name = serializers.CharField(max_length=255, required=True)
    parent_folder_id = serializers.UUIDField(required=False, allow_null=True)  # Optional for root folders

    def validate(self, data):
        folder_name = data.get('folder_name')
        parent_folder_id = data.get('parent_folder_id')

        # Validate folder name
        if not folder_name:
            raise serializers.ValidationError({"folder_name": "Folder name cannot be empty."})

        # If a parent_folder_id is provided, validate its existence
        if parent_folder_id:
            try:
                parent_folder = Folder.objects.get(id=parent_folder_id)
                # Check if a folder with the same name already exists under the parent
                if Folder.objects.filter(name=folder_name, parent=parent_folder).exists():
                    raise serializers.ValidationError({"folder_name": "A folder with that name already exists in the parent folder."})
            except Folder.DoesNotExist:
                raise serializers.ValidationError({"parent_folder_id": "The parent folder does not exist."})
        else:
            if Folder.objects.filter(name=folder_name, owner=self.context['request'].user).exists():
                raise serializers.ValidationError({"folder_name": "A folder with that name already exists."})

        return data


    
# class FolderCreateAPIView(APIView):
#     serializer_class = FolderCreateSerializer
#     permission_classes = [IsAuthenticated]
#     parser_classes = [JSONParser]

#     def post(self, request):
#         serializer = FolderCreateSerializer(data=request.data)
        
#         if serializer.is_valid():
#             folder_name = serializer.validated_data['folder_name']
#             parent_folder_id = serializer.validated_data.get('parent_folder_id', None)

#             # Create root folder or subfolder
#             parent_folder = None
#             if parent_folder_id:
#                 parent_folder = get_object_or_404(Folder, id=parent_folder_id)
#                 if not parent_folder.is_editor(request.user.id):
#                     return Response({"responseText": "You do not have permission to create subfolders here."}, status=status.HTTP_403_FORBIDDEN)

#             new_folder = Folder.objects.create(name=folder_name, parent=parent_folder, owner=request.user)

#             # Handle shared folder logic for subfolder inheritance
#             if parent_folder and parent_folder.owner != request.user:
#                 for sharing in SharedFolder.objects.filter(shared_by=request.user, folder=parent_folder):
#                     SharedFolder.objects.get_or_create(user=sharing.user, shared_by=request.user, folder=new_folder, role=sharing.role)

#                 SharedFolder.objects.get_or_create(user=parent_folder.owner, folder=new_folder, shared_by=request.user, role=3)

#             return Response({
#                 "responseText": "Folder has been created successfully.",
#                 "folder_id": new_folder.id,
#                 "parent_folder_id": parent_folder.id if parent_folder else None  # Include parent folder id if it exists
#             }, status=status.HTTP_201_CREATED)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FolderCreateAPIView(APIView):
    serializer_class = FolderCreateSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    @extend_schema(
        request=FolderCreateSerializer,
        description="API for creating folder. Folder id will be required if folder is not created in root directory. Authentication required."
    )
    def post(self, request):
        serializer = FolderCreateSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            folder_name = serializer.validated_data['folder_name']
            parent_folder_id = serializer.validated_data.get('parent_folder_id', None)

            # Get the parent folder if provided
            if parent_folder_id:
                parent_folder = get_object_or_404(Folder, id=parent_folder_id)
                
                # Check if user has permission to add subfolder in the parent folder
                if not parent_folder.is_editor(request.user.id):
                    if parent_folder.has_perm(request.user.id):
                        return Response({"responseText": "You do not have permission to create subfolders here."}, status=status.HTTP_403_FORBIDDEN)
                    return Response({"responseText": "Parent folder not found."}, status=status.HTTP_404_NOT_FOUND)
            else:
                parent_folder = None  # No parent folder, it's a root-level folder
            
            # Create the new folder
            new_folder = Folder.objects.create(name=folder_name, parent=parent_folder, owner=request.user)

            # Handle shared folder logic (just like your initial code)
            if parent_folder and parent_folder.owner != request.user:
                if SharedFolder.objects.filter(shared_by=request.user, folder=parent_folder).exists():
                    for sharing in SharedFolder.objects.filter(shared_by=request.user, folder=parent_folder):
                        SharedFolder.objects.get_or_create(user=sharing.user, shared_by=request.user, folder=new_folder, role=sharing.role)
                
                SharedFolder.objects.get_or_create(user=parent_folder.owner, folder=new_folder, shared_by=request.user, role=3)

            return Response({
                "responseText": "Folder has been created successfully.",
                "folder_id": new_folder.id,
                "parent_folder_id": parent_folder.id if parent_folder else None  # Include parent folder id if it exists
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetSerializer(serializers.Serializer):
    password1 = serializers.CharField(write_only=True, min_length=8, required=True)
    password2 = serializers.CharField(write_only=True, min_length=8, required=True)
    uidb64 = serializers.CharField(max_length=1000, required=True)
    token = serializers.CharField(max_length=1000, required=True)

    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

# Password Reset API view
@extend_schema(
    request=PasswordResetSerializer,
    description=""
)
class PasswordResetAPIView(APIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        
        if serializer.is_valid():
            uidb64 = serializer.validated_data['uidb64']
            token = serializer.validated_data['token']
            User = get_user_model()
            try:  
                uid = force_str(urlsafe_base64_decode(uidb64))  
                user = User.objects.get(pk=uid)  
            except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
                return Response({"responseText": "Invalid link"}, status=status.HTTP_400_BAD_REQUEST)
            
            if user is not None and PasswordResetTokenGenerator().check_token(user, token):
                # Reset user password
                user.set_password(serializer.validated_data['password1'])
                user.save()

                return Response({"responseText": "Password reset successful."}, status=status.HTTP_200_OK)
            else:
                return Response({"responseText": "Invalid token or user"}, status=status.HTTP_400_BAD_REQUEST)

        response = {'responseText': []}
        for key in serializer.errors.keys():
            for err in serializer.errors[key]:
                response['responseText'].append(err)
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

def generate_download_signed_url(file, user, expiry_seconds=300):
    signer = TimestampSigner()
    value = f"{file.id}:{user.id}"
    signed_value = signer.sign(value)
    expiry_timestamp = timedelta(seconds=expiry_seconds).total_seconds()
    
    # Include the expiry time in the query parameters
    query_params = urlencode({'expiry': expiry_timestamp})
    url = reverse('serve_download_file', args=[signed_value])
    
    return f"{url}?{query_params}"

@login_required
def download_signed_file(request, signed_value):
    signer = TimestampSigner()
    try:
        # Extract expiry time from the query parameters
        expiry_seconds = request.GET.get('expiry')
        
        # Validate the signed value and ensure the link hasn't expired
        original_value = signer.unsign(signed_value, max_age=float(expiry_seconds))
        file_id, user_id = original_value.split(':')
        
        # Ensure the user is the owner or has access
        file = get_object_or_404(File, id=file_id)
        if file.has_perm(request.user.id):
            encrypted_file_path = apply_correct_path(file.get_full_path())
            with open(encrypted_file_path, 'rb') as f:
                encrypted_content = f.read()
            decryptor = Fernet(key=settings.FILE_ENCRYPTION_KEY)
            decrypted_content = decryptor.decrypt(encrypted_content)

            # Serve the decrypted file for download (in-memory)
            response = FileResponse(decrypted_content, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file.name}"'
            return response
        else:
            return HttpResponseForbidden("You do not have permission to access this file.")
    
    except SignatureExpired:
        return HttpResponseForbidden("This link has expired.")
    
    except BadSignature:
        return HttpResponseForbidden("Invalid URL.")


class FileDownloadSerializer(serializers.Serializer):
    file_id = serializers.UUIDField(help_text="ID of the file to download")


@extend_schema(
    request=FileDownloadSerializer,
    description="API for downloading files.",

)

# @api_view(['GET'])
# def download_file(request):
#     file_id = request.GET.get('file_id')
    
#     # Ensure file_id is provided
#     if not file_id:
#         return Response({"status": 403, "responseText": "File id is required"}, status=403)
    
#     # Fetch the file object, or return 404 if it doesn't exist
#     file = get_object_or_404(File, id=file_id)
    
#     # Check if the user is authenticated
#     if request.user.is_authenticated:
        
#         # Check if the user has permission to download the file
#         if not file.has_perm(request.user.id):
#             return HttpResponseForbidden("You do not have permission to access this file.")
        
#         # Generate the signed URL for the file
#         download_url = generate_download_signed_url(file, request.user)
        
#         # Return the signed URL in the response
#         return Response({"status": 200, "download_url": download_url}, status=200)
    
#     else:
#         # Handle public access to files (if allowed)
#         if file.access_everyone:
#             # Generate the signed URL for public access
#             download_url = generate_download_signed_url(file, request.user)
            
#             # Return the signed URL in the response
#             return Response({"status": 200, "download_url": download_url}, status=200)
        
#         # If the user isn't allowed access and the file isn't public
#         return HttpResponseForbidden("You do not have permission to access this file.")
    
@api_view(['GET'])
class DownloadFile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        file_id = request.GET.get('file_id')
        if not file_id:
            return Response({"status": 403, "responseText": "File id is required"})
        file = get_object_or_404(File, id=file_id)
        if request.user.is_authenticated:
            # Get the file object

            # Check if the user has permission to access the file
            if not file.has_perm(request.user.id):
                return HttpResponseForbidden("You do not have permission to access this file.")
            
            
            url = generate_download_signed_url(file, request.user)
            return redirect(to=url)
        else:
            if file.access_everyone:
                url = generate_download_signed_url(file, request.user)
                return redirect(to=url)
            return HttpResponseForbidden("You do not have permission to access this file.")

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'name', 'size', 'owner', 'starred']


class UserFileSerializer(serializers.ModelSerializer):
    owner = serializers.CharField(source='owner.username', read_only=True)
    
    class Meta:
        model = File
        fields = ['name', 'owner', 'description', 'upload_date', 'last_accessed', 'size']  # Include all required fields

# Added
class UserFilesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Fetch all files uploaded by the authenticated user
        user_files = File.objects.filter(owner=request.user, parent=None)

        # Serialize the files
        serializer = UserFileSerializer(user_files, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class FolderSerializer(serializers.ModelSerializer):
    subfolders = serializers.SerializerMethodField()
    files = serializers.SerializerMethodField()
    owner = serializers.CharField(source='owner.username', read_only=True)

    class Meta:
        model = Folder
        fields = ['name', 'owner', 'created_at', 'subfolders', 'files']

    def get_subfolders(self, obj):
        # Serializing the subfolders of the folder
        subfolders = obj.subfolders.all()
        return FolderSerializer(subfolders, many=True).data

    def get_files(self, obj):
        # Serializing the files within the folder
        files = obj.subfiles.all()
        return FileSerializer(files, many=True).data
    
class FolderViewSerializer(serializers.Serializer):
    folder_id = serializers.CharField()

@extend_schema(
    request=FolderViewSerializer
)

class FolderViewAPIView(APIView):
    serializer_class = FolderViewSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request):
        # Validate folder_id in request query params
        folder_id = request.GET.get('folder_id')
        if not folder_id:
            return Response({"status": 400, "responseText": "folder_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the folder based on the provided folder_id
        try:
            folder = Folder.objects.get(id=folder_id)
        except:
            return Response({"status": 404, "responseText": "Folder not found"}, status=status.HTTP_404_NOT_FOUND)
        # Check if the user has permission to access the folder
        if not folder.has_perm(request.user.id):
            return Response({"status": 403, "responseText": "Access denied"}, status=status.HTTP_403_FORBIDDEN)

        # If the user is the owner, increase the access count
        if folder.owner == request.user:
            folder.access_count += 1
            folder.save()

        # Serialize the folder along with its subfolders and files
        serializer = FolderSerializer(folder)
        return Response(serializer.data, status=status.HTTP_200_OK)

        return Response({"responseText": "You do not have permission to view this folder."}, status=status.HTTP_403_FORBIDDEN)

def share_item_recursive(item, users, user):
    # If the item is a folder, share all subfolders and files
    if isinstance(item, Folder):
        for subfolder in item.subfolders.all():
            subfolder.access_list.add(users)
            try:
                SharedFolder.objects.create(
                    user=user,
                    folder=item,
                    shared_by=user
                )
            except Exception as e:
                print(f"Error sharing subfolder: {e}")
            share_item_recursive(subfolder, users, user)  # Recursively share subfolders
        for file in item.subfiles.all():
            try:
                SharedFile.objects.create(
                    user=user,
                    folder=item,
                    shared_by=user
                )
            except Exception as e:
                print(f"Error sharing file: {e}")
            file.access_list.add(users)


# class FolderViewAPIView(APIView):
#     serializer_class = FolderViewSerializer
#     permission_classes = [IsAuthenticated]
#     parser_classes = [JSONParser]

#     def get(self, request):
#         folder_id = request.GET.get('folder_id')
#         folder = get_object_or_404(Folder, id=folder_id)

#         # Check if the user has permission to access the folder
#         # if folder.has_perm(request.user.id):
            
#             # Increase access count if the folder owner is the current user
#         if folder.owner == request.user:
#             folder.access_count += 1
#             folder.save()

#         if not folder.has_perm(request.user.id):
#             return Response({"status": 403, "responseText": "Access denied"})
#             # Serialize the folder, its subfolders, and files
#         serializer = FolderSerializer(folder)
#         return Response(serializer.data, status=status.HTTP_200_OK)

# def share_item_recursive(item, users, user):
#     # If the item is a folder, share all subfolders and files
#     if isinstance(item, Folder):
#         for subfolder in item.subfolders.all():
#             subfolder.access_list.add(users)
#             try:
#                 SharedFolder.objects.create(
#                         user=user,
#                         folder=item,
#                         shared_by=request.user
#                     )
#             except:
#                 pass
#             share_item_recursive(subfolder, users, user)  # Recursively share subfolders
#         for file in item.subfiles.all():
#             try:
#                 SharedFile.objects.create(
#                         user=user,
#                         folder=item,
#                         shared_by=user
#                     )
#             except:
#                 pass
#             file.access_list.add(users)

# Add all folders for a user endpoint
# class FolderSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Folder
#         fields = ['id', 'name', 'parent', 'owner', 'created_at']


class UserFoldersAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # Get root-level folders owned by the user (where parent is None)
        user_owned_folders = Folder.objects.filter(owner=user, parent=None)

        # Get root-level folders shared with the user (where parent is None)
        shared_folders = Folder.objects.filter(
            id__in=SharedFolder.objects.filter(user=user).values_list('folder_id', flat=True),
            parent=None  # Ensure these are also root-level folders
        )

        # Combine both sets of root-level folders
        user_folders = user_owned_folders | shared_folders

        # Serialize folder data
        serializer = FolderSerializer(user_folders, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

class AllFoldersAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # Get folders owned by the user
        user_owned_folders = Folder.objects.filter(owner=user)

        # Get folders shared with the user
        shared_folders = Folder.objects.filter(
            id__in=SharedFolder.objects.filter(user=user).values_list('folder_id', flat=True)
        )

        # Combine both sets of folders
        user_folders = user_owned_folders | shared_folders

        # Serialize folder data
        serializer = FolderSerializer(user_folders, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class ShareFolderAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        folder_instance = get_object_or_404(Folder, id=folder_id)

        # Check if the user has permission to share the folder
        if folder_instance.is_editor(request.user.id):
            usernames = request.data.get('usernames', '')
            share_with_everyone = request.data.get('everyone', False)
            friend_to_share = request.data.get('friends', [])
            role = request.data.get('userRole', 1)  # Default role is Viewer (1)
            # Parse the usernames and friends list
            usernames = [username.strip() for username in usernames.split(',') if username.strip()]

            for friend in friend_to_share:
                try:
                    usernames.append(CustomUser.objects.get(username=friend).username)
                except:
                    pass
            messages = []

            # If not sharing with everyone
            if not share_with_everyone:
                if folder_instance.access_everyone:
                    messages.append("This folder has been removed from everyone's view")
                folder_instance.access_everyone = False
                folder_instance.save()
                # Share with specific users
                for username in usernames:
                    user = CustomUser.objects.filter(username=username).first()
                    if user and user != request.user:
                        try:
                            shared_folder, created = SharedFolder.objects.get_or_create(
                                user=user,
                                folder=folder_instance,
                                defaults={
                                    'shared_by': request.user,
                                    'role': role
                                }
                            )
                            if not created:
                                # Update if already shared
                                shared_folder.shared_by = request.user
                                shared_folder.role = role
                                shared_folder.save()

                            share_item_recursive(folder_instance, user, request.user)
                            messages.append(f'{folder_instance.name} shared with {user.username}')
                        except Exception as e:
                            messages.append(f'Failed to share with {username} due to: {str(e)}')
                    else:
                        messages.append(f'Failed to share with {username} (invalid username or sharing with yourself).')
            else:
                # Share with everyone
                folder_instance.access_everyone = True
                folder_instance.save()
                messages.append(f'{folder_instance.name} shared with everyone')

            return Response({'status': 200, 'responseText': 'Folder shared with selection'}, status=status.HTTP_200_OK)

        return Response({'status': 403, 'responseText': 'You do not have permission to share this folder'}, status=status.HTTP_403_FORBIDDEN)

    def get(self, request):
        folder_id = request.GET.get('folder_id')
        folder_instance = get_object_or_404(Folder, id=folder_id)

        # Check permissions for viewing the shared users
        if folder_instance.is_editor(request.user.id):
            shared_list = SharedFolder.objects.filter(shared_by=request.user, folder=folder_instance)
            shared_with_everyone = folder_instance.access_everyone

            return Response({
                'folder_name': folder_instance.name,
                'shared_list': [
                    {
                        'user': shared.user.username,
                        'role': shared.get_role_display(),
                    } for shared in shared_list
                ],
                'shared_with_everyone': shared_with_everyone,
            }, status=status.HTTP_200_OK)

        return Response({'status': 403, 'responseText': 'You do not have permission to view shared users'}, status=status.HTTP_403_FORBIDDEN)

class StarFolderSerializer(serializers.Serializer):
    folder_id = serializers.CharField()

class StarFolderAPIView(APIView):
    serializer_class = StarFolderSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        folder_id = request.data.get('folder_id')  # Use request.data for JSON requests
        try:
            folder = Folder.objects.get(id=folder_id)  # Fetch folder by folder_id, not user id

            # Check if the user is the folder owner or has access
            if request.user != folder.owner:
                if not (folder.has_perm(request.user.id)):
                    return Response({"status": 403, "responseText": "You do not have access to this item"}, status=403)
            
            # If user is the owner
            if folder.owner == request.user:
                folder.starred = not folder.starred  # Toggle the starred status
            else:
                user = request.user
                if user.starred_folders.contains(folder):
                    user.starred_folders.remove(folder)  # Unstar folder for non-owner
                else:
                    user.starred_folders.add(folder)  # Star folder for non-owner
                user.save()

            folder.save()
            return Response({"status": 200, "responseText": "This folder has been successfully starred"}, status=200)

        except Folder.DoesNotExist:
            return Response({"status": 404, "responseText": "This folder cannot be found"}, status=404)
        
# class StarFolderAPIView(APIView):
#     serializer_class = StarFolderSerializer
#     parser_classes = [JSONParser]

#     def post(self, request):
#         folder_id = request.POST.get('folder_id')
#         try:
#             folder = Folder.objects.get(id=request.user)
#             if request.user != folder.owner:
#                 if not (folder.access_list.contains(request.user) or folder.access_everyone or SharedFolder.objects.filter(folder=folder, user=request.user).exists()):
#                     return Response({"status": 403, "responseText": "You do not have access to this item"}, status=403)
#             if folder.owner == request.user:
#                 if folder.starred:
#                     folder.starred = False
#                 else:
#                     folder.starred = True
#             else:
#                 user = request.user
#                 if user.starred_folders.contains(folder):
#                     user.starred_folders.remove(folder)
#                     user.save()
#                 else:
#                     user.starred_folders.add(folder)
#                     user.save()
#             folder.save()
#             return Response({"status": 200, "responseText": "This folder has been successfully starred"}, status=200)        
#         except:
#             return Response({"status": 404, "responseText": "This folder cannot be found"}, status=404)

class BinFolderSerializer(serializers.Serializer):
    folder_id = serializers.CharField()

class BinFolderAPIView(APIView):
    serializer_class = BinFolderSerializer
    parser_classes = [JSONParser]  # To parse incoming JSON data
    permission_classes = [IsAuthenticated]

    def post(self, request):
        folder_id = request.data.get('folder_id')  # Use request.data for JSON body
        try:
            folder = Folder.objects.get(id=folder_id)
            
            # Permission check: if user is not the owner and has no permission
            if request.user != folder.owner:
                if not folder.has_perm(request.user.id):
                    return Response({"status": 403, "responseText": "You do not have permission to access this folder"}, status=403)
                folder.deny_access(request.user.id)
            else:
                # Toggle binned state
                if not folder.binned:
                    folder.binned = datetime.now()
                    folder.save()
                else:
                    if folder.parent:
                        if not folder.parent.binned:
                            folder.binned = None
                            folder.save()
                        else:
                            folder.parent = None
                            folder.binned = None
                            folder.save()
                    else:
                        folder.binned = None
                        folder.save()

            return Response({"status": 200, "responseText": "This folder has been successfully binned"}, status=200)

        except Folder.DoesNotExist:
            return Response({"status": 404, "responseText": "This folder was not found"}, status=404)

# class BinFolderAPIView(APIView):
#     serializer_class = BinFolderSerializer
#     parser_classes = [JSONParser]

#     def post(self, request):
#         folder_id = request.POST.get('folder_id')
#         try:
#             folder = Folder.objects.get(id=folder_id)
#             if request.user != folder.owner:
#                 if not folder.has_perm(request.user.id):
#                     return  Response({"status": 403, "responseText": "You do not have permission to access this file"}, status=403)
#                 folder.deny_access(request.user.id)
#             else:
#                 if not folder.binned:
#                     folder.binned = datetime.now()
#                     folder.save()
#                 else:
#                     if folder.parent:
#                         if not folder.parent.binned:
#                             folder.binned = None
#                             folder.save()
#                         else:
#                             folder.parent = None
#                             folder.binned = None
#                             folder.save()
#                     else:
#                         folder.binned = None
#                         folder.save()
#             return Response({"status": 200, "responseText": "This folder has been successfully binned"}, status=200)
#         except:
#             return Response({"status": 404, "responseText": "This folder was not found"})

class DeletePermAPIView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        folder_id = request.data.get('folder_id')  # Corrected to use request.data for JSON payloads
        if not folder_id:
            return Response({"status": 400, "responseText": "folder_id is required"}, status=400)

        try:
            folder = Folder.objects.get(id=folder_id)
        except Folder.DoesNotExist:
            return Response({"status": 404, "responseText": "This folder was not found."}, status=404)

        # Check if the user is the owner of the folder
        if folder.owner == request.user:
            folder.delete()  # If the user is the owner, delete the folder
            return Response({"status": 200, "responseText": "This folder has been successfully deleted"}, status=200)
        
        # Check if the user has permission to the folder (shared access)
        elif folder.has_perm(request.user.id):
            folder.deny_access(request.user.id)  # Deny the user's access if they have permission
            return Response({"status": 200, "responseText": "You have denied your access to this folder"}, status=200)
        
        # If the user neither owns nor has permission to the folder
        return Response({"status": 403, "responseText": "You do not have access to this folder"}, status=403)


# class DeletePermAPIView(APIView):
#     serializer_class = StarFolderSerializer
#     parser_classes = [JSONParser]

#     def post(self, request):
#         folder_id = request.POST.get('folder_id')
#         try:
#             folder = Folder.objects.get(id=folder_id)
#             if folder.owner == request.user:
#                 folder.delete()
#                 return Response({"status": 200, "responseText": "This folder has been successfully deleted"}, status=200)
#             elif folder.has_perm(request.user.id):
#                 folder.deny_access(request.user.id)
#                 return Response({"status": 200, "responseText": "You have deniec your access to this folder"})
#             else:
#                 return Response({"status": 403, "responseText": "You do not have access to this folder"}, status=403)
#         except:
#             return Response({"status": 404, "responseText": "This folder was not found."}, status=404)
        
class CopySharedFolderAPIView(APIView):
    serializer_class = StarFolderSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        try:
            folder_instance =   Folder.objects.get(id=folder_id)
            if not folder_instance.has_perm(request.user.id):
                return Response({"status": 403, "responseText": "You do not have access to this folder"}, status=403)

            folder_directory = os.path.join(settings.MEDIA_ROOT, folder_instance.get_path())

            root_folder = Folder.objects.create(
                name=folder_instance.name,
                parent=None,
                owner=request.user
            )
    
            root_path = os.path.join(settings.MEDIA_ROOT, root_folder.get_path())
            shutil.copytree(folder_directory, root_path, dirs_exist_ok=True)

            for root, dirs, files in os.walk(folder_directory):
                relative_path = os.path.relpath(root, folder_directory)
                if relative_path != '.':
                    parent_folder, created = Folder.objects.get_or_create(
                        name=os.path.basename(root),
                        parent=root_folder if relative_path == '.' else parent_folder,
                        owner=request.user
                    )
                else:
                    parent_folder = root_folder

                # Create subfolders in the database
                for dir_name in dirs:
                    Folder.objects.create(
                        name=dir_name,
                        parent=parent_folder,
                        owner=request.user
                    )


                # Create file entries in the database
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    relative_file_path = os.path.relpath(file_path, settings.MEDIA_ROOT)
                    file_size = os.path.getsize(file_path)  # Get the file size in bytes

                    File.objects.create(
                        name=file_name,
                        file=relative_file_path,
                        owner=request.user,
                        parent=parent_folder,
                        size=file_size  # Set the file size
                    )
            return Response({"status": 200, "responseText": "This folder has been copied to your drive"})
        except Exception as e:
            return Response({"status": 404, "responseText": "This folder does not exist."}, status=404)

encryptor = Fernet(settings.FILE_ENCRYPTION_KEY)
def is_binary_file(file_path, block_size=512):
    """
    Check whether a file is binary or text by reading its content.
    Reads a portion of the file and checks if it's mostly ASCII or UTF-8.
    """
    with open(file_path, 'rb') as file:
        block = file.read(block_size)
        if b'\0' in block:
            return True  # If there are null bytes, it is likely a binary file.
        
        # Try to detect the encoding of the file
        result = chardet.detect(block)
        encoding = result['encoding']
        
        if encoding is None:
            return True  # If no encoding detected, assume binary
        
        # Check if encoding is UTF-8 or other text-based encoding
        try:
            block.decode(encoding)
            return False  # Successfully decoded, so it's a text file
        except (UnicodeDecodeError, LookupError):
            return True 
def get_image_extension(image_data):
    from PIL import Image
    import io
    image = Image.open(io.BytesIO(image_data))
    return image.format.lower()
def decrypt_chunks(file_instance):
    cipher_suite = Fernet(settings.FILE_ENCRYPTION_KEY)
    with open(file_instance.file.path, 'rb') as encrypted_file:
        while True:
            chunk = encrypted_file.read(8192)  # Read file in chunks
            if not chunk:
                break
            yield cipher_suite.decrypt(chunk)

def convert_image(image_data, file_id):
    from PIL import Image
    import io
    # Create a hash of the image data
    image_hash = hashlib.md5(image_data).hexdigest()

    image_extension = get_image_extension(image_data)
    image_name = f'{image_hash}.{image_extension}'
    # Set the image path using the hash
    image_path = apply_correct_path(os.path.join('secure_doc_media', f'{image_hash}.{image_extension}'))

    # Check if the image already exists
    if os.path.exists(image_path):
        return reverse('serve_img', args=[file_id, image_name])
    
    default_storage.save(image_path, io.BytesIO(image_data))

    # Create the image if it doesn't exist

    return reverse('serve_img', args=[file_id, image_name])

def process_html_for_secure_images(html_content, file_id):
    from bs4 import BeautifulSoup
    import requests

    soup = BeautifulSoup(html_content, 'html.parser')

    for img_tag in soup.find_all('img'):
        img_url = img_tag['src']
        if img_url.startswith('data:image'):
            header, encoded = img_url.split(",", 1)
            image_data = base64.b64decode(encoded)
            secure_image_url = convert_image(image_data, file_id)
            img_tag['src'] = secure_image_url
        else:
            response = requests.get(img_url)
            if response.status_code == 200:
                image_data = response.content
                secure_image_url = convert_image(image_data, file_id)
                img_tag['src'] = secure_image_url

    return str(soup)

@login_required
def serve_secure_doc_image(request, image_name, file_id):
    # Get the file object
    file = get_object_or_404(File, id=file_id)
    # Construct the image path
    image_path = apply_correct_path(os.path.join('secure_doc_media', image_name))

    # Check if the image exists
    if not os.path.exists(image_path):
        raise Http404("Image not found")

    # Serve the image securely
    if file.has_perm(request.user.id):
        return FileResponse(open(image_path, 'rb'))
    return HttpResponseForbidden("You cannot view this image")

def secure_image_urls(document_html, file_id):
    # Regex pattern to find image URLs
    pattern = re.compile(r'<img src="([^"]+)"')
    
    # Replace image URLs with a secure Django view URL
    def replace_url(match):
        original_url = match.group(1)
        # Generate a secure URL to serve the image
        secure_url = reverse('serve_img', args=[file_id, original_url.split('/')[-1]])
        return f'<img src="{secure_url}"'
    
    return re.sub(pattern, replace_url, document_html)

def generate_signed_url(file, user, expiry_seconds=300):
    signer = TimestampSigner()
    value = f"{file.id}:{user.id}"
    signed_value = signer.sign(value)
    expiry_timestamp = timedelta(seconds=expiry_seconds).total_seconds()
    
    # Include the expiry time in the query parameters
    query_params = urlencode({'expiry': expiry_timestamp})
    url = reverse('serve_signed_file', args=[signed_value])
    
    return f"{url}?{query_params}"

class ShareFileAPIView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        folder_id = request.GET.get('folder_id')
        folder_instance = get_object_or_404(Folder, id=folder_id)

        # Check permissions for viewing the shared users
        if folder_instance.is_editor(request.user.id):
            shared_list = SharedFolder.objects.filter(shared_by=request.user, folder=folder_instance)
            shared_with_everyone = folder_instance.access_everyone

            return Response({
                'folder_name': folder_instance.name,
                'shared_list': [
                    {
                        'user': shared.user.username,
                        'role': shared.get_role_display(),
                    } for shared in shared_list
                ],
                'shared_with_everyone': shared_with_everyone,
            }, status=status.HTTP_200_OK)

        return Response({'status': 403, 'responseText': 'You do not have permission to view shared users'}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        try:
            file_instance = File.objects.get(id=folder_id)
            if request.method == 'POST':
                if file_instance.has_perm(request.user.id):
                    usernames = request.POST.get('usernames', '')
                    role = request.POST.get('userRole', '1')
                    share_with_everyone = request.POST.get('everyone', False)
                    friend_to_share = request.POST.getlist('friends')
                
                    usernames = [username.strip() for username in usernames.split(',') if username.strip() and CustomUser.objects.filter(username=username.strip()).exists()]
                
                    for friend in friend_to_share:
                        try:
                            usernames.append(CustomUser.objects.get(id=friend).username)
                        except:
                            pass
                    # print(usernames)

                    messages = []
                    if not share_with_everyone:
                        for username in usernames:
                            user = CustomUser.objects.filter(username=username).first()
                            print(file_instance)
                            file_instance.access_list.add(user)
                            print(file_instance.access_list.all())
                            file_instance.save()
                            if user and user != request.user:
                                try:
                                    SharedFile.objects.update_or_create(
                                        user=user,
                                        file=file_instance,
                                        shared_by=request.user,
                                        role=role
                                    )
                                except:
                                    pass
                                messages.append(f'{file_instance.name} shared with {user.username}')
                            else:
                                messages.append(f'Failed to share with {username} (invalid username or sharing with yourself).')
                    else:
                        file_instance.access_everyone = True
                        file_instance.save()
                        messages.append(f'{file_instance.name} shared with everyone')

                return Response({"status": 403, "responseText": "Access denied"}, status=status.HTTP_403_FORBIDDEN)
            return Response({'status': 200, 'responseText': "File shared with selected users."})
        except:
            return Response({"status": 404, "responseText": "This file was not found."})

class FileBaseSerializer(serializers.Serializer):
    file_id = serializers.UUIDField()

class StarFileAPIView(APIView):
    serializer_class = FileBaseSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Use request.data to get file_id (handles both JSON and form data)
        file_id = request.data.get('file_id')

        # Check if file_id is provided
        if not file_id:
            return Response({"status": 400, "responseText": "File ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Pass `file_id` as data to the serializer for validation
        serializer = self.serializer_class(data={'file_id': file_id})

        if serializer.is_valid():
            # Extract validated file_id
            file_id = serializer.validated_data['file_id']
            try:
                # Get the file by ID
                file = File.objects.get(id=file_id)

                # Check if the user has permission to star/unstar the file
                if not file.has_perm(request.user.id):
                    return Response({"status": 403, "responseText": "Action denied"}, status=status.HTTP_403_FORBIDDEN)

                # If the request user is the file owner, toggle the file's `starred` field
                if file.owner == request.user:
                    file.starred = not file.starred  # Toggle starred status
                else:
                    # If the user is not the owner, star/unstar it for the user's starred files
                    user = request.user
                    if user.starred_files.contains(file):
                        user.starred_files.remove(file)  # Unstar the file
                    else:
                        user.starred_files.add(file)  # Star the file
                    user.save()

                # Save the file (needed if owner stars/unstars it)
                file.save()

                # Return response based on whether the file is starred or not
                is_starred = file.starred or request.user.starred_files.contains(file)
                response_text = "This file has been starred." if is_starred else "This file has been unstarred."

                return Response({"status": 200, "responseText": response_text}, status=status.HTTP_200_OK)

            except File.DoesNotExist:
                # Return 404 if file is not found
                return Response({"status": 404, "responseText": "This file was not found"}, status=status.HTTP_404_NOT_FOUND)

        else:
            # Return serializer errors if validation fails
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FileBaseSerializer(serializers.Serializer):
    file_id = serializers.UUIDField()


# class StarFileAPIView(APIView):
#     serializer_class = FileBaseSerializer
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         file_id = request.POST.get('file_id')
#         # Pass `file_id` as data to the serializer
#         serializer = self.serializer_class(data={'file_id': file_id})
#         # serializer = self.serializer_class(file_id)
#         if serializer.is_valid():
#             file_id = serializer.validated_data['file_id']  # Extract validated `file_id`
#             try:
#                 file = File.objects.get(id=file_id)
#                 if not file.has_perm(request.user.id):
#                     return Response({"status": 403, "responseText": "Action denied"}, status=status.HTTP_403_FORBIDDEN)
#                 if file.owner == request.user:
#                     if file.starred:
#                         file.starred = False
#                     else:
#                         file.starred = True
#                 else:
#                     user = request.user
#                     if user.starred_files.contains(file):
#                         user.starred_files.remove(file)
#                     else:
#                         user.starred_files.add(file)
#                     user.save()
#                 file.save()
#                 return Response({"status": 200, "responseText": "This file has been starred." if file.starred or request.user.starred_files.contains(file) else "This file has been unstarred"}, status=status.HTTP_200_OK)
#             except:
#                 return Response({"status": 404, "responseText": "This file was not found"}, status=status.HTTP_404_NOT_FOUND)
            
def get_file_or_404(model, item_id):
    try:
        return model.objects.binned_items().get(id=item_id)
    except model.DoesNotExist:
        try:
            return model.objects.all_with_binned().get(id=item_id)
        except model.DoesNotExist:
            raise Http404("Item does not exist or is binned")

class BinFileAPIView(APIView):
    serializer_class = FileBaseSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file_id = request.data.get('file_id')
        if not file_id:
            return Response({"status": 400, "responseText": "File ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(data={'file_id': file_id})
        if serializer.is_valid():
            file_id = serializer.validated_data['file_id']  # Extract validated file_id

            try:
                file = File.objects.get(id=file_id)
                if not file.is_editor(request.user.id):
                    if not file.has_perm(request.user.id):
                        return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
                if not file.binned:
                    file.binned = datetime.now()
                    file.save()
                    return Response({"status": 200, "responseText": "This file has been moved to bin"}, status=status.HTTP_200_OK)
                else:
                    file.binned = None
                    file.save()
                    return Response({"status": 200, "responseText": "This file has been restored"}, status=status.HTTP_200_OK)

            except File.DoesNotExist:
                return Response({"status": 404, "responseText": "This file was not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class BinFileAPIView(APIView):
#     serializer_class = FileBaseSerializer
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         # Retrieve file_id from request.data (handles both JSON and form data)
#         file_id = request.data.get('file_id')

#         # Check if file_id is provided in the request
#         if not file_id:
#             return Response({"status": 400, "responseText": "File ID is required."}, status=status.HTTP_400_BAD_REQUEST)

#         # Pass file_id as data to the serializer for validation
#         serializer = self.serializer_class(data={'file_id': file_id})

#         # Validate the serializer data
#         if serializer.is_valid():
#             file_id = serializer.validated_data['file_id']  # Extract validated file_id

#             try:
#                 # Fetch the file using the file_id
#                 file = File.objects.get(id=file_id)

#                 # Permission check: ensure user has the necessary permissions
#                 if not file.is_editor(request.user.id):
#                     if not file.has_perm(request.user.id):
#                         return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
                
#                 # If the user has permission, remove the file from the user's access list
#                 else:
#                     file.access_list.remove(request.user)
#                     file.save()

#                     # Remove any shared file record if it exists
#                     if SharedFile.objects.filter(user=request.user, file=file).exists():
#                         SharedFile.objects.get(user=request.user, file=file).delete()

#                     return Response({"status": 200, "responseText": "You have removed this file from your view."}, status=status.HTTP_200_OK)

#                 # Bin the file or restore it based on its current state
#                 if not file.binned:
#                     file.binned = datetime.now()
#                     file.save()
#                     return Response({"status": 200, "responseText": "This file has been moved to bin"}, status=status.HTTP_200_OK)
#                 else:
#                     file.binned = None
#                     file.save()
#                     return Response({"status": 200, "responseText": "This file has been restored"}, status=status.HTTP_200_OK)
            
#             except File.DoesNotExist:
#                 return Response({"status": 404, "responseText": "This file was not found."}, status=status.HTTP_404_NOT_FOUND)

#         # If serializer data is invalid, return the validation errors
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class BinFileAPIView(APIView):
#     serializer_class = FileBaseSerializer
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         file_id = request.POST.get('file_id')
#         serializer = self.serializer_class(file_id)
#         if serializer.is_valid():
#             file_id = serializer.validated_data['file_id']  # Extract validated `file_id`
#             try:
#                 file = File.objects.get(id=file_id)
#                 if not file.is_editor(request.user.id):
#                     if not file.has_perm(request.user.id):
#                         return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
#                 else:
#                     file.access_list.remove(request.user)
#                     file.save()
#                     if SharedFile.objects.filter(user=request.user, file=file).exists():
#                         SharedFile.objects.get(user=request.user, file=file).delete()
#                     return Response({"status": 200, "responseText": "You have removed this file from your view."}, status=status.HTTP_200_OK)
#                 if not file.binned:
#                     file.binned = datetime.now()
#                     file.save()
#                     return Response({"status": 200, "responseText": "This file has been moved to bin"}, status=status.HTTP_200_OK)
#                 else:
#                     file.binned = None
#                     file.save()
#                     return Response({"status": 200, "responseText": "This file has been restored"}, status=status.HTTP_200_OK)
#             except:
#                 return Response({"status": 404, "responseText": "This file was not found."}, status=status.HTTP_404_NOT_FOUND)

class FolderBaseSerializer(serializers.Serializer):
    folder_id = serializers.UUIDField()

class UnzipFileAPIView(APIView):
    serializer_class = FileBaseSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(request.data)
        if serializer.is_valid():
            try:
                file = File.objects.get(id=request.POST.get('file_id'))
                if not file.is_editor(request.user.id):
                    return Response({"status": 403, "responseText": "Action denied."}, status=status.HTTP_403_FORBIDDEN)
                if not file.get_extension() == "zip":
                    return Response({"responseText": "You are trying to unzip a non zip file.", "status": 403}, status=status.HTTP_403_FORBIDDEN)
                
                file_path = apply_correct_path(file.get_full_path())
                unzip_dir = os.path.join(os.path.splitext(file_path)[0])
                print(unzip_dir)

                try:
                    os.makedirs(os.path.dirname(unzip_dir))
                except:
                    pass

                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(unzip_dir)

                root_folder = file.parent
                parent_folder = Folder.objects.create(
                    name=file.name.replace('.zip', ''),
                    parent=root_folder,
                    owner=request.user
                )  

                # Iterate through all directories and files in the unzipped content
                for root, dirs, files in os.walk(unzip_dir):
                    # Calculate the relative path from the root of the unzipped directory
                    relative_path = os.path.relpath(root, unzip_dir)

                #     # Find or create the current parent folder in the database, starting from the root folder
                    if relative_path != '.':
                        parent_folder, created = Folder.objects.get_or_create(
                            name=os.path.basename(root),
                            parent=root_folder if relative_path == '.' else parent_folder,
                            owner=request.user
                        )
                    else:
                        parent_folder

                    # Create subfolders in the database
                    for dir_name in dirs:
                        Folder.objects.get_or_create(
                            name=dir_name,
                            parent=parent_folder,
                            owner=request.user
                        )

                    # Create file entries in the database
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        relative_file_path = os.path.relpath(file_path, settings.MEDIA_ROOT)
                        file_size = os.path.getsize(file_path)  # Get the file size in bytes

            # Create the file entry in the correct folder in the database
                        File.objects.create(
                            name=file_name,
                            file=relative_file_path,
                            owner=request.user,
                            parent=parent_folder,
                            size=file_size  # Set the file size
                        )
                return Response({"status": 200, "responseText": "This file has been unzipped."}, status=status.HTTP_200_OK)
            except:
                return Response({"status": 404, "responseText": "This file was not found."}, status=status.HTTP_404_NOT_FOUND)
            
def create_zip_file(folder, save_path):
    """
    Create a zip file of the folder and save it to the specified path.
    
    :param folder: The Folder object to be zipped.
    :param save_path: The path where the zip file should be saved.
    :return: The path to the created zip file.
    """
    folder_path = apply_correct_path(folder.get_path())
    zip_filename = os.path.join(save_path, f"{folder.name}.zip")
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, os.path.join(folder_path, '..'))
                zip_file.write(file_path, arcname)
    
    return zip_filename


class ZipFolderAPIView(APIView):
    serializer_class = FolderBaseSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                folder_id = request.data.get('folder_id')
                if not folder_id:
                    return Response({"status": 400, "responseText": "Folder ID is required"}, status=status.HTTP_400_BAD_REQUEST)
                
                folder = Folder.objects.get(id=folder_id)
                
                # Check if user has permission to zip the folder
                if not folder.is_editor(request.user.id):
                    return Response({"status": 403, "responseText": "Action denied"}, status=status.HTTP_403_FORBIDDEN)

                save_path = folder.parent.get_path() if folder.parent else os.path.join(settings.MEDIA_ROOT, request.user.username)

                zip_file = create_zip_file(folder, save_path)

                File.objects.create(
                    name=f"{folder.name}.zip",
                    file=zip_file,
                    owner=request.user,
                    size=os.path.getsize(zip_file),
                    parent=folder.parent
                )

                return Response({"status": 200, "responseText": "Folder zipped successfully", "file_id": file}, status=status.HTTP_200_OK)

            except Folder.DoesNotExist:
                return Response({"status": 404, "responseText": "Folder not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                # Log the exact error for debugging
                print(f"Error during zipping: {e}")  # Debugging
                raise e
                return Response({"status": 500, "responseText": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def add_folder_to_zip(self, zipf, folder):
        """
        Recursively add all files in the folder and its subfolders to the zip.
        """
        try:
            # Add files in the current folder to the zip
            for file_obj in folder.subfiles.all():
                # Ensure file_obj.name and file_obj.file.name are valid
                file_name = file_obj.name if file_obj.name else 'unnamed_file'
                file_path = file_obj.file.name

                if not file_path:
                    print(f"Skipping file with no path: {file_name}")  # Debugging
                    continue  # Skip if the file path is None

                # Read the file from Django's storage system
                with default_storage.open(file_path, 'rb') as file_content:
                    # Add file to zip with its name relative to the folder
                    zipf.writestr(file_name, file_content.read())

            # Recursively add subfolders
            for subfolder in folder.subfolders.all():
                subfolder_name = subfolder.name if subfolder.name else 'unnamed_folder'

                # Add subfolder structure to zip (even if empty)
                zipf.writestr(f"{subfolder_name}/", '')

                # Recursively add files from subfolder
                self.add_folder_to_zip(zipf, subfolder)

        except Exception as e:
            print(f"Error while adding folder to zip: {folder.name}, error: {e}")  # Debugging
            raise e


# class ZipFolderAPIView(APIView):
#     serializer_class = FolderBaseSerializer
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         serializer = self.serializer_class(request.data)
#         if serializer.is_valid():
#             try:
#                 folder = Folder.objects.get(id=request.POST.get('folder_id'))
#                 if not folder.is_editor(request.user.id):
#                     return Response({"status": 403, "responseText": "Action denied"}, status=status.HTTP_403_FORBIDDEN)
#                 save_path = folder.parent.get_path() if folder.parent else os.path.join(settings.MEDIA_ROOT, request.user.username)

#                 zip_file = create_zip_file(folder, save_path)

#                 File.objects.create(
#                     name=f"{folder.name}.zip",
#                     file=zip_file,
#                     owner=request.user,
#                     size=os.path.getsize(zip_file),
#                     parent=folder.parent
#                 )
#             except:
#                 return Response({"status": 404, "responseText": "This folder was not found"}, status=status.HTTP_404_NOT_FOUND)

class DeletePermFileAPIView(APIView):
    serializer_class  = FileBaseSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(request.data)
        if serializer.is_valid():
            try:
                file = File.objects.get(id=request.POST.get('file_id'))
                if file.is_editor(request.user.id):
                    file.delete()
                    return Response({"status": 200, "responseText": "File has been deleted."}, status=status.HTTP_200_OK)
                elif file.has_perm(request.user.id):
                    file.deny_access(request.user.id)
                    return Response({"status": 200, "responseText": "Access to this file has been denied by you."}, status=status.HTTP_200_OK)
                else:
                    return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
    
            except:
                return Response({"status": 404, "responseText": "File not found."}, status=status.HTTP_404_NOT_FOUND)


# from django.core.files.storage import default_storage
# from django.core.files.base import ContentFile
# import shutil  # More robust way of copying/renaming files
# from django.db import transaction  # For atomic operations

# class RenameFileAPIView(APIView):
#     serializer_class = RenameFileSerializer
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         if serializer.is_valid():
#             try:
#                 # Get the file from the database using file_id
#                 file = File.objects.get(id=request.data.get('file_id'))
#                 new_name = request.data.get('new_name')

#                 # Check if the user has permission to edit the file
#                 if not file.is_editor(request.user.id):
#                     return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)

#                 # Get the current file's path and extension
#                 old_file_path = file.file.path  # Full path to the file
#                 file_extension = os.path.splitext(file.name)[1]  # Keep the current file extension
#                 new_file_name = f"{new_name}{file_extension}"
                
#                 # Ensure atomicity for database operations
#                 with transaction.atomic():
#                     # Build the new file path
#                     new_file_path = os.path.join(os.path.dirname(old_file_path), new_file_name)
                    
#                     # Use Django's storage system for renaming files
#                     if default_storage.exists(new_file_path):
#                         return Response({"status": 400, "responseText": "A file with the new name already exists."}, status=status.HTTP_400_BAD_REQUEST)

#                     # Rename/move file to the new path
#                     default_storage.save(new_file_path, ContentFile(default_storage.open(old_file_path).read()))
#                     default_storage.delete(old_file_path)  # Delete the old file
                    
#                     # Update the file object in the database
#                     file.name = new_file_name  # Update the file's name in the database
#                     file.file.name = os.path.relpath(new_file_path, settings.MEDIA_ROOT)  # Update the file field
#                     file.save()

#                 return Response({"status": 200, "responseText": "File renamed successfully."}, status=status.HTTP_200_OK)

#             except File.DoesNotExist:
#                 return Response({"status": 404, "responseText": "File not found."}, status=status.HTTP_404_NOT_FOUND)
#             except PermissionError:
#                 return Response({"status": 403, "responseText": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
#             except OSError as e:
#                 return Response({"status": 500, "responseText": f"File system error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#             except Exception as e:
#                 return Response({"status": 500, "responseText": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         return Response({"status": 400, "responseText": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)

class RenameFileSerializer(serializers.Serializer):
    file_id = serializers.UUIDField()
    override = serializers.BooleanField(default=False)
    new_name = serializers.CharField()

class RenameFolderSerializer(serializers.Serializer):
    folder_id = serializers.UUIDField()
    override = serializers.BooleanField(default=False)
    new_name = serializers.CharField()

class RenameFileAPIView(APIView):
    serializer_class = RenameFileSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                # Get the file from the database using file_id
                file = File.objects.get(id=request.data.get('file_id'))
                new_name = request.data.get('new_name')

                # Check if the user has permission to edit the file
                if not file.is_editor(request.user.id):
                    return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)

                # Get the current file's path and extension
                old_file_path = file.file.path  # Full path to the file
                file_extension = os.path.splitext(file.name)[1]  # Keep the current file extension
                
                # Build the new file name
                new_file_name = f"{new_name}{file_extension}"
                
                # Create the new full path with the new file name (keeping the same directory)
                new_file_path = os.path.join(os.path.dirname(old_file_path), new_file_name)

                # Rename the file in the file system
                os.replace(old_file_path, new_file_path)
                # os.rename(old_file_path, new_file_path)
                
                # Update the file's name and file field in the database
                file.name = new_file_name  # Update the name in the database
                file.file.name = os.path.relpath(new_file_path, settings.MEDIA_ROOT)  # Update the file path relative to MEDIA_ROOT
                file.save()

                return Response({"status": 200, "responseText": "File renamed successfully."}, status=status.HTTP_200_OK)

            except File.DoesNotExist:
                return Response({"status": 404, "responseText": "File not found."}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"status": 500, "responseText": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"status": 400, "responseText": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)


# class RenameFileAPIView(APIView):
#     serializer_class = RenameFileSerializer
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         serializer = self.serializer_class(request.data)
#         if serializer.is_valid():
#             try:
#                 file = File.objects.get(id=request.POST.get('file_id'))
#                 new_name = request.POST.get('new_name')
#                 if not file.is_editor(request.user.id):
#                     return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
#                 if not request.POST.get('override'):
#                     file_path = os.path.join(settings.MEDIA_ROOT, file.get_full_path())
#                     new_file_path = os.path.join(os.path.dirname(file_path), new_name)
#                     try:
#                         os.rename(file_path, new_file_path)
#                     except FileExistsError:
#                         return Response({"status": 403, "responseText": "A file with this name exists."}, status=status.HTTP_403_FORBIDDEN)
#                     file.file = new_file_path
#                     file.name = new_name
#                     file.save()
#                 else:
#                     file_path = os.path.join(settings.MEDIA_ROOT, file.get_full_path())
#                     new_file_path = os.path.join(os.path.dirname(file_path), new_name)
#                     if os.path.exists(new_file_path):
#                         os.remove(new_file_path)
#                     os.rename(file_path, new_file_path)
#                     file.file = new_file_path
#                     if File.objects.filter(parent=file.parent, name=new_name).exists():
#                         to_be_del = File.objects.get(parent=file.parent, name=new_name)
#                         to_be_del.delete()
#                     file.name = new_name
#                     file.save()
#                 return Response({"status": 200, "responseText": "File has been renamed successfully."}, status=status.HTTP_200_OK)
#             except:
#                 return Response({"status": 404, "responseText": "File not found."}, status=status.HTTP_404_NOT_FOUND)


class RenameFolderAPIView(APIView):
    serializer_class = RenameFolderSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                folder = Folder.objects.get(id=request.data.get('folder_id'))
                
                # Check permissions
                if not folder.is_editor(request.user.id):
                    return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
                
                new_name = request.data.get('new_name')
                
                # Check for name conflict in the same parent folder
                if Folder.objects.filter(parent=folder.parent, name=new_name).exists():
                    if request.data.get('override'):
                        # Delete conflicting folder if override is True
                        Folder.objects.filter(parent=folder.parent, name=new_name).delete()
                    else:
                        return Response({"status": 409, "responseText": "Folder with this name already exists."}, status=status.HTTP_409_CONFLICT)
                
                # Rename the folder in the database
                folder.name = new_name
                folder.save()

                return Response({"status": 200, "responseText": "Folder renamed successfully."}, status=status.HTTP_200_OK)
            
            except Folder.DoesNotExist:
                return Response({"status": 404, "responseText": "Folder not found."}, status=status.HTTP_404_NOT_FOUND)
            
            except Exception as e:
                return Response({"status": 500, "responseText": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({"status": 400, "responseText": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)
    
# class RenameFolderAPIView(APIView):
#     serializer_class = RenameFolderSerializer
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]
#     def post(self, request):
#         serializer = self.serializer_class(request.data)
#         if serializer.is_valid():
#             try:
#                 folder = Folder.objects.get(id=request.POST.get('folder_id'))
#                 if not folder.is_editor(request.user.id):
#                     return Response({"status": 403, "responseText": "Access denied."}, status=status.HTTP_403_FORBIDDEN)
#                 new_name = request.POST.get('new_name')
#                 if not request.POST.get('override'):
#                     file_path = os.path.join(settings.MEDIA_ROOT, folder.get_path())
#                 folder_path = apply_correct_path(folder.get_path())
#                 new_folder_path = os.path.join(os.path.dirname(folder_path), new_name)
#                 if os.path.exists(new_folder_path):
#                     shutil.rmtree(new_folder_path)
#                 os.rename(folder_path, new_folder_path)
#                 if Folder.objects.filter(parent=folder.parent, name=new_name).exists():
#                     to_be_del = Folder.objects.get(parent=folder, name=new_name)
#                     to_be_del.delete()
#                 folder.name = new_name
#                 folder.save()
#                 return Response({"status": 200, "responseText": "Folder renamed successfully."}, status=status.HTTP_200_OK)
#             except:
#                 return Response({"status": 404, "responseText": "Folder not found."}, status=status.HTTP_404_NOT_FOUND)
#         return Response({"status": 404, "responseText": "File not found."}, status=status.HTTP_404_NOT_FOUND)
    
class CopySharedFileAPIView(APIView):
    serializer_class = FileBaseSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(request.data)
        if serializer.is_valid():
            try:
                file = File.objects.get(id=request.POST.get('file_id'))
                if not file.has_perm(request.user.id):
                    return Response({"status": 403, "responseText": "Access denied"})
                File.objects.create(
                    name=file.name,
                    owner=request.user,
                    file=file.file,
                    parent=None,
                    size=file.size
                )
                return Response({"status": 200, "responseText": "File has been copied to yuor storage."}, status=status.HTTP_200_OK)
            except:
                return Response({"status": 404, "responseText": "File not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({"status": 404, "responseText": "File not found."}, status=status.HTTP_404_NOT_FOUND)
    
class MoveFileSerializer(serializers.Serializer):
    file_id = serializers.UUIDField()
    destination_folder_id = serializers.UUIDField(required=False)

    def validate(self, data):
        file_id = data.get('file_id')
        destination_folder_id = data.get('destination_folder_id')
        
        # Validate the file exists
        try:
            file = File.objects.get(id=file_id)
            data['file'] = file
        except File.DoesNotExist:
            raise serializers.ValidationError("The file does not exist.")
        
        # Validate the destination folder (optional if moving to 'home')
        if destination_folder_id:
            try:
                folder = Folder.objects.get(id=destination_folder_id)
                data['destination'] = folder
            except Folder.DoesNotExist:
                raise serializers.ValidationError("The destination folder does not exist.")
        
        return data

class MoveFileAPIView(APIView):
    serializer_class = MoveFileSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Move a file to a different folder or home directory.",
        request_body=MoveFileSerializer,
        responses={
            200: openapi.Response("File moved successfully."),
            400: openapi.Response("Bad request, file or destination not found."),
            403: openapi.Response("Permission denied."),
        }
    )
    def post(self, request):
        serializer = MoveFileSerializer(data=request.data)
        if serializer.is_valid():
            file = serializer.validated_data['file']
            destination = serializer.validated_data.get('destination')  # Optional destination

            if destination:
                if not (destination.owner == request.user or destination.is_shared_with(request.user, role=3)):
                    return Response({"status": "Error", "message": "You do not have permission to move to this destination."}, status=status.HTTP_403_FORBIDDEN)
            else:
                destination = None

            # Generate new file path
            file_name, ext = os.path.splitext(file.name)
            destination_path = destination.get_path() + f'/{file_name}{ext}' if destination else request.user.username + f'/{file_name}{ext}'
            
            counter = 1
            while os.path.exists(destination_path):
                destination_path = destination.get_path() + f'/{file_name} ({counter}){ext}' if destination else request.user.username + f'/{file_name} ({counter}){ext}'
                counter += 1

            # Check if file is already in the destination
            if file.parent == destination:
                return Response({"status": "Error", "message": "File is already in the destination."}, status=status.HTTP_400_BAD_REQUEST)

            # Move the file
            os.rename(file.get_full_path(), destination_path)
            file.name = os.path.basename(destination_path)
            file.file = destination_path
            file.parent = destination
            file.save()

            return Response({"status": "Success", "message": "File moved successfully."}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class MoveFolderSerializer(serializers.Serializer):
#     folder_id = serializers.UUIDField()
#     destination_folder_id = serializers.UUIDField(required=False)  # Destination is optional

#     # Validate and get the actual folder instances
#     def validate(self, data):
#         folder_id = data.get('folder_id')
#         destination_folder_id = data.get('destination_folder_id', None)
        
#         try:
#             folder = Folder.objects.get(id=folder_id)
#         except Folder.DoesNotExist:
#             raise serializers.ValidationError("Folder not found.")
        
#         if destination_folder_id:
#             try:
#                 destination = Folder.objects.get(id=destination_folder_id)
#             except Folder.DoesNotExist:
#                 raise serializers.ValidationError("Destination folder not found.")
#         else:
#             destination = None  # No destination means moving to root
        
#         data['folder'] = folder
#         data['destination'] = destination
#         return data

# class MoveFolderAPIView(APIView):
#     """
#     API View to move a folder to a different destination folder.
#     """
#     # serializer_class = MoveFolderSerializer
#     permission_classes = [IsAuthenticated]
#     parser_classes = [JSONParser]

#     def post(self, request):
#         serializer = MoveFolderSerializer(data=request.data)
#         if serializer.is_valid():
#             folder = serializer.validated_data['folder']
#             destination = serializer.validated_data.get('destination')  # Optional destination folder

#             # Ensure the user has permission to move the folder
#             if not folder.is_editor(request.user.id):
#                 return Response({"status": "Error", "message": "You do not have permission to move this folder."}, status=status.HTTP_403_FORBIDDEN)

#             if destination and not destination.is_editor(request.user.id):
#                 return Response({"status": "Error", "message": "You do not have permission to move to this destination."}, status=status.HTTP_403_FORBIDDEN)

#             # Prevent moving the folder into itself or its subfolders
#             if self.is_descendant(folder, destination):
#                 return Response({"status": "Error", "message": "Cannot move a folder into itself or one of its subfolders."}, status=status.HTTP_400_BAD_REQUEST)

#             # Generate new folder path
#             folder_name = folder.name
#             destination_path = os.path.join(destination.get_path() if destination else os.path.join(settings.MEDIA_ROOT, str(request.user.id)), folder_name)

#             # Normalize paths for compatibility
#             destination_path = os.path.normpath(destination_path)
#             source_path = os.path.normpath(folder.get_path())

#             # Check if the source folder path exists
#             # if not os.path.exists(source_path):
#             #     return Response({"status": "Error", "message": f"Source folder path not found: {source_path}"}, status=status.HTTP_400_BAD_REQUEST)

#             # Handle duplicate folder names in the destination
#             destination_path = self.handle_duplicate_names(destination, folder_name, destination_path)

#             # Move the folder physically in the filesystem
#             try:
#                 shutil.move(source_path, destination_path)
#             except Exception as e:
#                 return Response({"status": "Error", "message": f"Error moving folder: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#             # Update folder's parent in the database
#             folder.parent = destination
#             folder.save()

#             return Response({"status": "Success", "message": "Folder moved successfully."}, status=status.HTTP_200_OK)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def handle_duplicate_names(self, destination, folder_name, destination_path):
#         """Handle duplicate folder names in the destination by appending a counter."""
#         counter = 1
#         while os.path.exists(destination_path):
#             destination_path = os.path.join(destination.get_path() if destination else os.path.join(settings.MEDIA_ROOT, str(request.user.id)), f'{folder_name} ({counter})')
#             destination_path = os.path.normpath(destination_path)
#             counter += 1
#         return destination_path

#     def is_descendant(self, folder, destination):
#         """Check if the destination is a descendant of the folder."""
#         if destination is None:
#             return False
#         current = destination
#         while current:
#             if current == folder:
#                 return True
#             current = current.parent
#         return False



class MoveFolderSerializer(serializers.Serializer):
    folder_id = serializers.UUIDField()
    destination_folder_id = serializers.UUIDField(required=False, allow_null=True)

    def validate(self, data):
        folder_id = data.get('folder_id')
        destination_folder_id = data.get('destination_folder_id')

        # Validate that the folder exists
        try:
            folder = Folder.objects.get(id=folder_id)
            data['folder'] = folder
        except Folder.DoesNotExist:
            raise serializers.ValidationError("The folder does not exist.")

        # Validate the destination folder (if provided)
        if destination_folder_id:
            try:
                destination = Folder.objects.get(id=destination_folder_id)
                data['destination'] = destination
            except Folder.DoesNotExist:
                raise serializers.ValidationError("The destination folder does not exist.")

        return data

class MoveFolderAPIView(APIView):
    serializer_class = MoveFolderSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    @swagger_auto_schema(
        operation_description="Move a folder to a different folder or home directory.",
        request_body=MoveFolderSerializer,
        responses={
            200: openapi.Response("Folder moved successfully."),
            400: openapi.Response("Bad request, folder or destination not found."),
            403: openapi.Response("Permission denied."),
        }
    )
    def post(self, request):
        serializer = MoveFolderSerializer(data=request.data)
        if serializer.is_valid():
            folder = serializer.validated_data['folder']
            destination = serializer.validated_data.get('destination', None)  # Optional destination (None means move to root/home)

            # Check if the user has permission to move the folder
            if not folder.is_editor(request.user.id):
                return Response({"status": "Error", "message": "You do not have permission to move this folder."}, status=status.HTTP_403_FORBIDDEN)

            if destination:
                # Ensure the user has permission to move the folder to the destination
                if not (destination.owner == request.user or destination.is_editor(request.user.id)):
                    return Response({"status": "Error", "message": "You do not have permission to move to this destination."}, status=status.HTTP_403_FORBIDDEN)

                # Prevent moving a folder into itself or its subfolders
                if folder == destination:
                    return Response({"status": "Error", "message": "Cannot move folder into itself."}, status=status.HTTP_400_BAD_REQUEST)
                if folder in destination.subfolders.all():
                    return Response({"status": "Error", "message": "Cannot move folder into its subfolder."}, status=status.HTTP_400_BAD_REQUEST)

            # If no destination, set the folder as a root-level folder (parent = None)
            if destination is None:
                folder.parent = None
            else:
                # Move folder under the destination folder as a subfolder
                folder.parent = destination

            try:
                # Save the changes to the database
                folder.save()
            except Exception as e:
                return Response({"status": "Error", "message": f"Failed to move folder: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"status": "Success", "message": "Folder moved successfully."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class MoveFolderSerializer(serializers.Serializer):
#     folder_id = serializers.UUIDField()
#     destination_folder_id = serializers.UUIDField(required=False)

#     def validate(self, data):
#         folder_id = data.get('folder_id')
#         destination_folder_id = data.get('destination_folder_id')
        
#         # Validate the folder exists
#         try:
#             folder = Folder.objects.get(id=folder_id)
#             data['folder'] = folder
#         except Folder.DoesNotExist:
#             raise serializers.ValidationError("The folder does not exist.")
        
#         # Validate the destination folder (optional if moving to 'home')
#         if destination_folder_id:
#             try:
#                 destination = Folder.objects.get(id=destination_folder_id)
#                 data['destination'] = destination
#             except Folder.DoesNotExist:
#                 raise serializers.ValidationError("The destination folder does not exist.")
        
#         return data
    
# class MoveFolderAPIView(APIView):
#     serializer_class = MoveFolderSerializer
#     permission_classes = [IsAuthenticated]
#     parser_classes = JSONParser

#     @swagger_auto_schema(
#         operation_description="Move a folder to a different folder or home directory.",
#         request_body=MoveFolderSerializer,
#         responses={
#             200: openapi.Response("Folder moved successfully."),
#             400: openapi.Response("Bad request, folder or destination not found."),
#             403: openapi.Response("Permission denied."),
#         }
#     )
#     def post(self, request):
#         serializer = MoveFolderSerializer(data=request.data)
#         if serializer.is_valid():
#             folder = serializer.validated_data['folder']
#             destination = serializer.validated_data.get('destination', None)  # Optional destination

#             if destination:
#                 if not (destination.owner == request.user or destination.is_shared_with(request.user, role=3)):
#                     return Response({"status": "Error", "message": "You do not have permission to move to this destination."}, status=status.HTTP_403_FORBIDDEN)
#             else:
#                 destination = None

#             # Generate new folder path
#             folder_name = folder.name
#             destination_path = destination.get_path() + f'/{folder_name}' if destination else request.user.username + f'/{folder_name}'
            
#             counter = 1
#             while os.path.exists(destination_path):
#                 destination_path = destination.get_path() + f'/{folder_name} ({counter})' if destination else request.user.username + f'/{folder_name} ({counter})'
#                 counter += 1

#             # Prevent moving folder into itself
#             if folder == destination:
#                 return Response({"status": "Error", "message": "Cannot move folder into itself."}, status=status.HTTP_400_BAD_REQUEST)

#             # Move the folder
#             os.rename(folder.get_path(), destination_path)
#             folder.parent = destination
#             folder.save()

#             return Response({"status": "Success", "message": "Folder moved successfully."}, status=status.HTTP_200_OK)
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class ChangeRoleSerializer(serializers.Serializer):
    sharing_id = serializers.UUIDField()
    new_role = serializers.IntegerField()
    item_type = serializers.IntegerField()

    def validate(self, data):
        data['item_type'] = self.item_type
        if self.item_type == 0:
            try:
                file_shar = SharedFile.objects.get(id=self.sharing_id)
                data['sharing'] = file_shar
            except:
                raise serializers.ValidationError("Sharing id not valid or incorrect item type")
        elif self.item_type == 1:
            try:
                folder_shar = SharedFolder.objects.get(id=self.sharing_id)
                data['sharing'] = folder_shar
            except:
                raise serializers.ValidationError("Sharing id not valid or incorrect item type")
        else:
            raise serializers.ValidationError("Invalid item type. Enter a correct type.")
        return data
    
class ChangeRoleAPIView(serializers.Serializer):
    serializer_class = ChangeRoleSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(request.data)
        if serializer.is_valid():
            if serializer.validated_data['item_type'] == 1:
                sharedfolder = SharedFolder.objects.get(id=self.sharing_id, shared_by=request.user)
                sharedfolder.role = request.POST.get('new_role', sharedfolder.role)
                sharedfolder.save()
            else:
                sharedfile = SharedFile.objects.get(id=self.sharing_id, shared_by=request.user)
                sharedfile.role = self.new_role or sharedfile.role
                sharedfile.save()
            return Response({"status": 200, "responseText": "User role changed successfully."})
        return Response({"status": 403, "responseText": "Invalid data"}, status=status.HTTP_403_FORBIDDEN)

class RemoveRoleSerializer(serializers.Serializer):
    sharing_id = serializers.UUIDField()
    item_type = serializers.IntegerField()

    def validate(self, data):
        if self.item_type == 0:
            try:
                sharedfile = SharedFile.objects.get(id=data['sharing_id'])
                data['sharing'] = sharedfile
            except:
                raise serializers.ValidationError("Invalid sharing id")
        elif self.item_type == 1:
            try:
                sharedfolder = SharedFolder.objects.get(id=data['sharing_id'])
                data['sharing'] = sharedfolder
            except:
                raise serializers.ValidationError("Invalid sharing id")
        else:
            raise serializers.ValidationError("Invalid item type.")
        
class RemoveRoleAPIView(APIView):
    serializer_class = RemoveRoleSerializer
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(request.data)
        if serializer.is_valid():
            sharing = serializer.validated_data['sharing']
            if serializer.validated_data['item_type'] == 0:
                if sharing.file.access_list.contains(request.user):
                    sharing.file.access_list.remove(request.user)
                    sharing.file.save()
            else:
                if sharing.folder.access_list.contains(request.user):
                    sharing.folder.access_list.remove(request.user)
                    sharing.folder.save() 
            sharing.delete()
            return Response({"status": 200, "responseText": "Role removed successfully"}, status=status.HTTP_200_OK)

        return Response({"status": 403, "responseText": "invalid item type or sharing id."}, status=status.HTTP_403_FORBIDDEN)

class SuggestedFilesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        recent_folders = Folder.objects.filter(owner=request.user).order_by('-id')[:4]
        frequent_folders = Folder.objects.filter(owner=request.user).order_by('-access_count')[:4]
        shared_folders = Folder.objects.filter(access_list=request.user)[:4]

        # Fetch suggested files
        recent_files = File.objects.filter(owner=request.user).order_by('-last_accessed')[:4]
        frequent_files = File.objects.filter(owner=request.user).order_by('-access_count')[:4]
        shared_files = File.objects.filter(access_list=request.user)[:4]

        temp_suggested_folders = [
            {'folders': recent_folders, 'reason': 'Recently Accessed'},
            {'folders': frequent_folders, 'reason': 'Frequently Accessed'},
            {'folders': shared_folders, 'reason': 'Shared with You'},
        ]

        suggested_folders = [
            {'folders': [], 'reason': 'Recently Accessed'},
            {'folders': [], 'reason': 'Frequently Accessed'},
            {'folders': [], 'reason': 'Shared with You'},
        ]

        seen_folder_ids = set()
    
        for i in range(0, 3):
            for folder in temp_suggested_folders[i]['folders']:
                if folder.id not in seen_folder_ids:
                    suggested_folders[i]['folders'].append(folder)
                    seen_folder_ids.add(folder.id)



        temp_suggested_files = [
            {'files': recent_files, 'reason': 'Recently Accessed'},
            {'files': frequent_files, 'reason': 'Frequently Accessed'},
            {'files': shared_files, 'reason': 'Shared with You'},
        ]

        suggested_files = [
            {'files': [], 'reason': 'Recently Accessed'},
            {'files': [], 'reason': 'Frequently Accessed'},
            {'files': [], 'reason': 'Shared with You'},
        ]

        seen_file_ids = set()
        
        for i in range(0, 3):
            for file in temp_suggested_files[i]['files']:
                if file.id not in seen_file_ids:
                    suggested_files[i]['files'].append(file)
                    seen_file_ids.add(file.id)

class GetStarredFilesAPIView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from itertools import chain

        # Get folders owned by the user that are starred
        owned_starred_folders = Folder.objects.filter(owner=request.user, starred=True)

        # Get shared folders (via access_list) that are starred
        shared_starred_folders = Folder.objects.filter(access_list=request.user, starred=True)

        # Combine owned and shared folders
        combined_folders = list(chain(owned_starred_folders, shared_starred_folders))

        # Sort combined folders by created_at
        combined_folders = sorted(combined_folders, key=lambda f: f.created_at)

        # Get files owned by the user that are starred
        owned_starred_files = File.objects.filter(owner=request.user, starred=True)

        # Get shared files (via access_list or permission system) that are starred
        shared_starred_files = File.objects.filter(access_list=request.user, starred=True)

        # Combine owned and shared files
        combined_files = list(chain(owned_starred_files, shared_starred_files))

        # Sort combined files by upload_date
        combined_files = sorted(combined_files, key=lambda f: f.upload_date)

        # Return the response with both starred folders and starred files
        return Response({
            "status": 200,
            "my_starred_folders": FolderSerializer(combined_folders, many=True).data,
            "my_starred_files": FileSerializer(combined_files, many=True).data,
        })


# class GetStarredFilesAPIView(APIView):
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         from itertools import chain
#         from operator import attrgetter
#         folders = Folder.objects.filter(owner=request.user, starred=True)
#         my_starred_folders = request.user.starred_folders.all()
#         files = File.objects.filter(owner=request.user, starred=True)
#         my_starred_files = request.user.starred_files.all()

#         folders = sorted(chain(folders, my_starred_folders), key=lambda instance: instance.created_at)
#         files = sorted(chain(files, my_starred_files), key=lambda instance: instance.upload_date)

#         for file in range(0, len(files)):
#             if files[file].has_perm(request.user.id):
#                 pass
#             else:
#                 request.user.starred_files.remove(files[file])
#                 request.user.save()
#                 del files[file]

#         for folder in range(0, len(folders)):
#             if folders[folder].has_perm(request.user.id):
#                 pass
#             else:
#                 request.user.starred_folders.remove(folders[folder])
#                 request.user.save()
#                 del folders[folder]

#         return Response({ "status": 200, "my_starred_folders": my_starred_folders, "my_starred_files": my_starred_files})

class SharedFilesAPIView(APIView):
    parser_classes = [JSONParser]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        shared_folders = SharedFolder.objects.filter(user=request.user, visible=True)
        shared_files = SharedFile.objects.filter(user=request.user, visible=True)

        # Separate files and folders
        shared_files = [item.file for item in shared_files if item.file is not None]
        shared_folders = [item.folder for item in shared_folders if item.folder is not None]
        return Response({'files': shared_files, 'folders': shared_folders}, status=status.HTTP_200_OK)

from django.utils import timezone
class BinnedFilesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get the current user
        user = request.user

        # Get binned files and folders belonging to the current user
        binned_files = File.objects.binned_items().filter(owner=user)
        binned_folders = Folder.objects.binned_items().filter(owner=user)

        print("Binned files:", binned_files)
        print("Binned folders:", binned_folders)

        # Set the cutoff date for 30 days
        now = timezone.now()
        cutoff_date = now - timezone.timedelta(days=30)

        # Filter out items that should be deleted (older than 30 days)
        files_to_delete = binned_files.filter(binned__lte=cutoff_date)
        folders_to_delete = binned_folders.filter(binned__lte=cutoff_date)

        # Delete files and folders older than 30 days
        for file in files_to_delete:
            if os.path.exists(file.get_full_path()):
                os.remove(file.get_full_path())
            file.delete()

        for folder in folders_to_delete:
            folder_path = os.path.join(settings.MEDIA_ROOT, folder.get_path())
            if os.path.exists(folder_path):
                shutil.rmtree(folder_path)
            folder.delete()

        # Return the remaining binned items (not deleted)
        remaining_binned_files = binned_files.filter(binned__gt=cutoff_date)
        remaining_binned_folders = binned_folders.filter(binned__gt=cutoff_date)

        serialized_files = FileSerializer(remaining_binned_files, many=True)
        serialized_folders = FolderSerializer(remaining_binned_folders, many=True)

        # Return the full object data
        return Response({
            'binned_files': serialized_files.data,
            'binned_folders': serialized_folders.data,
        }, status=200)
        
# class BinnedFilesAPIView(APIView):
#     parser_classes = [JSONParser]
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         binned_files = File.objects.binned_items().filter(owner=request.user)
#         binned_folders = Folder.objects.binned_items().filter(owner=request.user)
#         from django.utils import timezone
#         now = timezone.now()
#         cutoff_date = now - timezone.timedelta(days=30)

#         files_to_delete = binned_files.filter(binned__lte=cutoff_date)
#         folders_to_delete = binned_folders.filter(binned__lte=cutoff_date)   

#         for file in files_to_delete:
#             if os.path.exists(file.get_full_path()):
#                 os.remove(file.get_full_path())
#             file.delete()

#         for folder in folders_to_delete:
#             if os.path.exists(folder.get_path()):
#                 os.remove(folder.get_path())
#             folder.delete()

#         return Response({
#             'binned_files': files_to_delete,
#             'binned_folders': folders_to_delete,
#         }, status=200)


# # Create your views here.


# def sign_up(request):
#     if request.method == 'POST':
#         form = RegistrationForm(request.POST)
#         if form.is_valid():
#             user = CustomUser.objects.create(username=request.POST.get('username'), full_name=request.POST.get('full_name'), email=request.POST.get('email'))
#             user.set_password(request.POST.get('password'))
#             user.is_active = False
#             user.save()
#             return JsonResponse(createBasicResponse(status=200, responseText="Check Your Email For Verification"), status=200)

#         return JsonResponse(createBasicResponse(status=302, responseText="There was an error", data=form.errors), status=302)
#     return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)

# def activate(request):
#     if request.method == "POST":
#         User = get_user_model()
#         uidb64 = request.POST.get('uidb64')
#         token = request.POST.get('token')  
#         try:  
#             uid = force_str(urlsafe_base64_decode(uidb64))  
#             user = User.objects.get(pk=uid)  
#         except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
#             user = None  
#         if user is not None and account_activation_token.check_token(user, token):  
#             user.is_active = True  
#             user.save()  
#             return JsonResponse({"status": "success", "msg": "Account has been activated"}, status=200) 
#         else:  
#             return JsonResponse(createBasicResponse(status=403, data="", responseText="Invalid URL"), status=403)
#     return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)

# def login(request):
#     if request.method == "POST":
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#         user = authenticate(username, password)
#         if user is not None:
#             login(request, user)
#             return JsonResponse(createBasicResponse(status=200, responseText="You have been logged in"), status=200)
#         else:
#             return JsonResponse(createBasicResponse(status=400, responseText="Invalid Username or Pass"), status=400)
#     return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)
