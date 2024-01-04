from rest_framework import serializers
from . import models


class PhoneNumberSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.NumberVerification
        fields = ('phone_number','otp')


class OtpVerifiySerializer(serializers.ModelSerializer):
    class Meta:
        model = models.NumberVerification
        fields = '__all__'


class GetNumber(serializers.Serializer):
    phone_number = serializers.IntegerField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CustomUser
        fields = ['email', 'first_name', 'last_name', 'gender', 'password','is_staff','is_superuser','phone_number']


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class UserSerializers(serializers.ModelSerializer):
    class Meta:
        model = models.CustomUser
        fields = '__all__'


class UserUpdateSerializer(serializers.Serializer):
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    phone_number = serializers.IntegerField(required=False)


class ProductRiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ProductRice
        fields = '__all__'


class UpdateProductSerializer(serializers.Serializer):
    product_name = serializers.CharField(required=False)
    product_price_1kg = serializers.FloatField(required=False)
    product_photo = serializers.ImageField(required=False)
    description = serializers.CharField(required=False)
    benefits = serializers.CharField(required=False)
    availability = serializers.IntegerField(required=False)


class GetProductSerializer(serializers.Serializer):
    product_name = serializers.CharField()


class ProductPulseSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ProductPulses
        fields = '__all__'


class CompanyDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.VrihodhaDetails
        fields = '__all__'


class CompanyDetailsCustomSerializer(serializers.Serializer):
    company_logo = serializers.ImageField()
    company_number = serializers.IntegerField()
    company_address = serializers.JSONField()
    terms_and_conditions = serializers.FileField()
    privacy_policy = serializers.CharField()
    about_us = serializers.CharField()


class VrihodhaDetailsSerializer(serializers.Serializer):
    choice = [('company_number', 'company_number'),
              ('company_address', 'company_address'),
              ('terms&conditions', 'terms&conditions'),
              ('privacy_policy', 'privacy_policy'),
              ('about_us', 'about_us')]
    details = serializers.ChoiceField(choices=choice)


class UserFeedBackSerializer(serializers.Serializer):
    feedback = serializers.CharField()
    email = serializers.EmailField()


class OrderProductSerializer(serializers.Serializer):
    product_name = serializers.CharField(required=True)
    quantity = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)


class AddAddressSerializer(serializers.Serializer):
    name = serializers.CharField()
    street = serializers.CharField(required=False)
    state = serializers.CharField(required=False)
    zip_code = serializers.IntegerField()
    country = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)


class AddressListSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.DeliveryAddress
        fields = '__all__'


class FeedbackListSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserFeedback
        fields = '__all__'


class OrderListSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.OrderDetails
        fields = '__all__'