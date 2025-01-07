import re

from rest_framework import serializers, status
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.http import JsonResponse

from django.contrib.auth import authenticate

from auths.models import ProjectUser


class RegistrationSerializer(serializers.ModelSerializer):

    password = serializers.CharField(write_only=True, help_text="The user's password.")

    confirm_password = serializers.CharField(write_only=True, help_text="Confirm the user's password.")

    """
    Serializer for user registration.
    Validates that the user's nickname, email, and password meet specific criteria.
    Passwords must match and must meet strength requirements.
    """

    class Meta:

        model = ProjectUser

        fields = ['nickname', 'username', 'email', 'password', 'confirm_password']
        help_texts = {
            'nickname': 'Unique nickname for the user.',
            'username': 'User’s full name.',
            'email': 'User’s email address.',
        }

    def validate_nickname(self, value):

        """Ensure the nickname is unique and doesn't exist in the database."""

        if ProjectUser.objects.filter(nickname=value).exists():

            raise serializers.ValidationError("User with this nickname already exists.")

        return value

    def validate_email(self, value):

        """Ensure the email is valid and unique in the database."""

        email_pattern = r'^[a-zA-Z0-9.%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$'

        if not re.match(email_pattern, value):

            raise serializers.ValidationError("Invalid email format.")

        if ProjectUser.objects.filter(email=value).exists():

            raise serializers.ValidationError("User with this email already exists.")

        return value

    def validate_password(self, value):

        """
        Ensure the password meets specific strength requirements:
        - At least 8 characters
        - Contains at least one digit
        - Contains at least one special character
        """

        pattern = r'^(?=.*[!@#$%^&()+}{":;\'?/>.<,`~])(?=.*\d)[^\s]{8,}$'

        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Password must be at least 8 characters long, contain at least one digit, "
                "contain at least one special character, and not have any spaces."
            )

        return value

    def validate(self, attrs):

        """Ensure the password and confirm password fields match."""

        if attrs['password'] != attrs['confirm_password']:

            raise serializers.ValidationError({"confirm_password": "Passwords must match."})

        return attrs

    def create(self, validated_data):

        """Create the user instance and set the password securely."""

        validated_data.pop('confirm_password')

        user = ProjectUser(**validated_data)

        user.set_password(validated_data['password'])

        user.save()

        return user


class RegistrationConfirmSerializer(serializers.Serializer):

    """Serializer for confirming user registration with a confirmation code.
    Validates that the code is a 6-digit number.
    """

    code = serializers.IntegerField()

    def validate_code(self, value):

        if value < 100000 or value > 999999:

            raise serializers.ValidationError("Invalid Code.")

        return value


class AuthorizationSerializer(serializers.Serializer):

    """
    Serializer for user login.
    Validates the nickname and password for authentication.
    """

    token_time = serializers.IntegerField()

    nickname = serializers.CharField()

    password = serializers.CharField()

    def validate(self, attrs):

        """Validates the provided credentials (nickname and password)."""

        nickname = attrs.get('nickname')

        password = attrs.get('password')

        if nickname is None or password is None:

            raise serializers.ValidationError({
                                        "errors": {
                                            "nickname": "Field are required.",
                                            "password": "Field are required."
                                            }
                                        })

        user = authenticate(username=nickname, password=password)

        if user is None:

            try:

                user = ProjectUser.objects.get(email=nickname)

            except ProjectUser.DoesNotExist:

                try:

                    user = ProjectUser.objects.get(nickname=nickname)

                except ProjectUser.DoesNotExist:

                    raise serializers.ValidationError({"nickname": "User does not exist."})

            if not user.check_password(password):

                raise serializers.ValidationError({'password': 'Wrong password.'})

        attrs['user'] = user

        return attrs


class LogoutResponseSerializer(serializers.Serializer):

    message = serializers.CharField(default='You don\'t need submit any data. Only <<refreshToken>> cookie')


class RequestPasswordRecoverySerializer(serializers.Serializer):

    email = serializers.EmailField()

    """
    Serializer for requesting a password recovery code.
    Validates that the email exists in the database.
    """
    
    def validate_email(self, value):

        """ Ensure the provided email is associated with an existing user."""

        try:

            user = ProjectUser.objects.get(email=value)

        except ProjectUser.DoesNotExist:

            raise serializers.ValidationError("User with this email does not exist.")

        return value


class PasswordRecoverySerializer(serializers.Serializer):

    """
    Serializer for confirming password recovery.
    Validates the recovery code, new password, and password confirmation.
    """

    code = serializers.IntegerField()

    password = serializers.CharField()

    confirm_password = serializers.CharField()

    def validate_password(self, value):

        """Ensure the new password meets the strength requirements."""

        pattern = r'^(?=.*[!@#$%^&()+}{":;\'?/>.<,`~])(?=.*\d)[^\s]{8,}$'

        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Password must be at least 8 characters long, contain at least one digit, "
                "contain at least one special character, and not have any spaces."
            )

        return value

    def validate_code(self, value):

        """Ensure the recovery code is a valid 6-digit number."""

        if value < 100000 or value > 999999:

            raise serializers.ValidationError("Invalid Code.")

        return value

    def validate(self, attrs):

        """Ensure the password and confirm password fields match."""

        if attrs['password'] != attrs['confirm_password']:

            raise serializers.ValidationError({"confirm_password": "Passwords must match."})

        return attrs


