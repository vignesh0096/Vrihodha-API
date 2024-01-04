from django.contrib.auth import get_user_model
from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser,PermissionsMixin


class NumberVerification(models.Model):
    phone_number = models.BigIntegerField(unique=True)
    otp = models.IntegerField()
    authorize = models.BooleanField(default=False)


class UserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        # if not email:
        #     raise ValueError("The email is not given.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.is_active = True
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if not extra_fields.get('is_staff'):
            raise ValueError("Superuser must have is_staff = True")

        if not extra_fields.get('is_superuser'):
            raise ValueError("Superuser must have is_superuser = True")
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    GENDER_CHOICES = (
        (1, 'male'),
        (2, 'female'),
        (3, 'other')
    )
    email = models.EmailField(max_length=254, unique=True)
    phone_number = models.BigIntegerField()
    password = models.CharField(max_length=128, null=True)
    first_name = models.CharField(max_length=255, null=True, blank=True)
    last_name = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    gender = models.SmallIntegerField(choices=GENDER_CHOICES)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password','gender','first_name','phone_number']

    objects = UserManager()

    def __str__(self):
        return self.email


class ProductRice(models.Model):
    product_name = models.CharField(max_length=100,blank=True)
    product_price_1kg = models.FloatField(blank=True)
    product_photo = models.ImageField(blank=True,height_field=None,width_field=None,
                                      upload_to='rice_uploads/')
    description = models.CharField(blank=True,max_length=500)
    benefits = models.CharField(blank=True, max_length=500)
    cooking_method = models.ImageField(blank=True,height_field=None,width_field=None,
                                       upload_to='rice_uploads/')
    availability = models.IntegerField(null=True,blank=True)


class ProductPulses(models.Model):
    product_name = models.CharField(max_length=100,blank=True)
    product_price_1kg = models.FloatField(blank=True)
    product_photo = models.ImageField(blank=True,height_field=None,width_field=None,
                                      upload_to='pulse_uploads/')
    description = models.CharField(blank=True,max_length=500)
    benefits = models.CharField(blank=True, max_length=500)
    availability = models.IntegerField(null=True,blank=True)


class VrihodhaDetails(models.Model):
    company_logo = models.ImageField(blank=True,height_field=None,width_field=None,
                                     upload_to='vrihodha_uploads/')
    company_number = models.BigIntegerField(null=True, blank=True)
    company_mail = models.EmailField(null=True,blank=True)
    company_address = models.JSONField(null=True,blank=True)
    terms_and_conditions = models.FileField(blank=True,upload_to='vrihodha_uploads/')
    privacy_policy = models.CharField(max_length=500,blank=False)
    about_us = models.CharField(max_length=500,blank=False)


class OrderDetails(models.Model):
    user_id = models.ForeignKey('CustomUser', models.DO_NOTHING)
    orders = models.JSONField(blank=False)


class DeliveryAddress(models.Model):
    user_id = models.ForeignKey('CustomUser', models.DO_NOTHING)
    address = models.JSONField(blank=False)


class UserFeedback(models.Model):
    user_id = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    feedback = models.JSONField(blank=False)

    objects = models.Manager()