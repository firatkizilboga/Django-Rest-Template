from datetime import timedelta

from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager,
                                        PermissionsMixin)
from django.core.mail import send_mail
from django.db import models
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.conf import settings
from . import app_settings


class UserManager(BaseUserManager):
    #docsting
    """ 
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        try:
            email_verification = EmailVerification.objects.create(user=user)
        except Exception as e:
            user.delete()
            raise ValueError('Email could not be sent')
            return None
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and save a SuperUser with the given email and password. is_staff and is_superuser are set to True
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model where email is the unique identifiers
    for authentication instead of usernames.
    """
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    email_verified = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [
                        'first_name',
                        'last_name'
                      ]

    def __str__(self):
        return self.first_name + ' ' + self.last_name
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if not self.email_verified:
            try:
                email_verification = EmailVerification.objects.create(user=self)
            except Exception as e:
                self.delete()
                raise ConnectionAbortedError('Email could not be sent')
        

class AdminUser(User):
    """
    Proxy model for admin user automatically created as staff
    """
    class Meta:
        """
        defines a proxy model
        """
        proxy = True

    def save(self, *args, **kwargs):
        """
        Set is_staff to True
        """
        self.is_staff = True
        super().save(*args, **kwargs)
    

class EmailVerification(models.Model):
    """
    Model for email verification
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    key = models.CharField(max_length=100, unique=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):

        """
        Set expires_at to 24 hours from created_at
        """
        #try to generate a random string of 100 characters if it already exists, generate another one
        string = get_random_string(length=100)
        while EmailVerification.objects.filter(key=string).exists():
            string = get_random_string(length=100)


        self.key = string
        self.expires_at = timezone.now() + timedelta(hours=24)

        super().save(*args, **kwargs)
        self.send_verification_email()



    def send_verification_email(self):
        """
        Send verification email to the user
        """
        recipient = self.user
        token = self.key
        subject = 'Verify your email'
        message = render_to_string('verification_email.html', {
            'token': token,
            'FRONTEND_URL': app_settings.FRONTEND_URL,
        })
        recipient_list = [recipient.email]


        send_mail(
            subject=subject,
            message=message,
            recipient_list=recipient_list,
            fail_silently=False,
            from_email=settings.EMAIL_HOST_USER,
            html_message=message,
        )


    def verify(self):
        """
        Confirm email
        """
        self.user: User

        if self.expires_at < timezone.now():
            #new confirmation object is created
            EmailVerification.objects.create(user=self.user)
            #delete the old one
            self.delete()
            raise ValueError('The confirmation key has expired')

        self.user.email_verified = True
        self.user.save()
        self.delete()
        return True
    
    @property
    def is_expired(self):
        """
        Check if the confirmation key has expired
        """
        return self.expires_at < timezone.now()

    def __str__(self):
        self.user.email: str
        self.key: str
        return self.user.email, self.key