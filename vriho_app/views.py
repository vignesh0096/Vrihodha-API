from django.shortcuts import render
from django.contrib.auth import authenticate, get_user_model
from .serializer import *
from rest_framework.generics import CreateAPIView, UpdateAPIView, DestroyAPIView, RetrieveAPIView, GenericAPIView,ListAPIView
from . import models
from rest_framework.permissions import DjangoModelPermissions
import random
from rest_framework.response import Response
from rest_framework import status
import bcrypt
from django.contrib.auth.hashers import make_password
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth.models import Group, Permission,ContentType
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.authentication import TokenAuthentication


class NumberVerify(CreateAPIView):
    serializer_class = GetNumber
    queryset = models.NumberVerification.objects.all()
    permission_classes = [AllowAny]

    """ Number registration and OTP generation API"""

    def post(self, request, *args, **kwargs):
        existing = models.NumberVerification.objects.filter(phone_number=request.data['phone_number'])
        try:
            if not existing:
                otp = random.randrange(1000, 9999)
                data = {'phone_number': request.data['phone_number'],
                        'otp': otp}
                serializer = PhoneNumberSerializer(data=data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                data_response = {
                    'response_code': status.HTTP_200_OK,
                    'message': "Number Registered and otp sent successfully",
                    'status_flag': True,
                    'status': "success",
                    'error_details': None,
                    'data': {'user': serializer.data},
                }
                return Response(data_response)
            else:
                data_response = {
                    'response_code': status.HTTP_400_BAD_REQUEST,
                    'message': "Number already Registered",
                    'status_flag': False,
                    'status': "Failed",
                }
                return Response(data_response)

        except Exception as e:
            return Response({
                'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'INTERNAL_SERVER_ERROR',
                'status_flag': False,
                'status': "Failed",
                'error_details': str(e),
                'data': []})


class OtpVerification(UpdateAPIView):
    serializer_class = PhoneNumberSerializer
    permission_classes = [AllowAny]

    """ Number and OTP Verification API"""

    def put(self, request, *args, **kwargs):
        existing = models.NumberVerification.objects.get(phone_number=request.data['phone_number'])
        if request.data['phone_number'] == existing.phone_number and request.data['otp'] == existing.otp:
            data = {'phone_number': existing.phone_number,
                    'otp': existing.otp,
                    'authorize': True}
            serializer = OtpVerifiySerializer(instance=existing, data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            data_response = {
                'response_code': status.HTTP_200_OK,
                'message': "otp verified succesfully",
                'status_flag': True,
                'status': "success",
                'error_details': None,
                'data': {'user': serializer.data},
            }
            return Response(data_response)
        else:
            data_response = {
                'response_code': status.HTTP_400_BAD_REQUEST,
                'message': "otp incorrect",
                'status_flag': False,
                'status': "Failed",
            }
            return Response(data_response)


class UserRegister(GenericAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    """User Registration API"""

    def post(self, request, *args, **kwargs):
        try:
            user = models.CustomUser.objects.filter(email=request.data['email']).first()
            if not user:
                number_verify = models.NumberVerification.objects.filter(phone_number=request.data['phone_number']).first()
                if number_verify and number_verify.authorize == 1:
                    serializer = UserSerializers(data=request.data)
                    hashed_password = make_password(request.data['password'])

                    if serializer.is_valid():
                        serializer.validated_data['password'] = hashed_password
                        serializer.save()
                    else:
                        return Response({'status_code':status.HTTP_404_NOT_FOUND,
                                         'message': 'Enter valid credentials'})
                else:
                    return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                     'message': 'verify your number'})
            else:
                return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                 'message': "user exist"})
            data_response = {
                'response_code': status.HTTP_200_OK,
                'message': "Registered successfully",
                'status_flag': True,
                'status': "success",
                'error_details': None,
                'data': serializer.data
            }
            return Response(data_response)
        except Exception as e:
            return Response({
                'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': "Something went wrong",
                'status_flag': False,
                'status': "Failed",
                'error': str(e),
            })


class UserLogin(GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    """Admin Login API"""

    def post(self, request, *args, **kwargs):
        try:
            User = get_user_model()
            user = User.objects.filter(email=request.data['email']).first()
            if not user:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "email not registered",
                                 'status_flag': False,
                                 'status': "Failed"})
            validate = authenticate(username=request.data['email'], password=request.data['password'])
            if not validate:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Password incorrect",
                                 'status_flag': False,
                                 'status': "Failed"})
            if user.is_staff == True and user.is_superuser == False:
                create_group, created = Group.objects.get_or_create(name='staff')
                if create_group or created:
                    group = Group.objects.get(name='staff')
                    user.groups.add(group.id)
                    content_type = ContentType.objects.filter(app_label='vriho_app')
                    model_name = ['productrice','productpulses','customuser']
                    model = [i.id for i in content_type if i.model in model_name]
                    for j in model:
                        get_permission = Permission.objects.filter(content_type_id=j)
                        for k in get_permission:
                            user.user_permissions.add(k.id)
                    # perm = Permission.objects.filter(content_type_id=con.id)
                    # for p in perm:
                    #     user.user_permissions.add(p.id)
                    # con1 = ContentType.objects.get(model='productrice')
                    # perm1 = Permission.objects.filter(content_type_id=con1.id)
                    # for p1 in perm1:
                    #     user.user_permissions.add(p1.id)
            elif user.is_staff == True and user.is_superuser == True:
                create_group, created = Group.objects.get_or_create(name='Admin')
                if create_group or created:
                    content_type = ContentType.objects.filter(app_label='vriho_app')
                    print(content_type)
                    every_model = [i.id for i in content_type]
                    group = Group.objects.get(name='Admin')
                    for j in every_model:
                        get_permission = Permission.objects.filter(content_type_id=j)
                        for k in get_permission:
                            user.groups.add(group.id)
                            user.user_permissions.add(k.id)
            elif user.is_staff == False and user.is_superuser == False:
                create_group, created = Group.objects.get_or_create(name='User')
                if create_group or created:
                    perm_list = ['add_customuser', 'change_customuser', 'view_customuser','view_productpulses',
                                 'view_productrice','view_vrihodhadetails','add_deliveryaddress','delete_deliveryaddress',
                                 'add_userfeedback','add_orderdetails','delete_orderdetails']
                    group = Group.objects.get(name='User')
                    for perm in perm_list:
                        perm_id = Permission.objects.get(codename=perm)
                        user.groups.add(group.id)
                        user.user_permissions.add(perm_id)
            token, created = Token.objects.get_or_create(user=user)

            data_response = {
                'response_code': status.HTTP_200_OK,
                'message': "Logged in successfully",
                'status_flag': True,
                'status': "success",
                'error_details': None,
                'token': str(token)
            }
            return Response(data_response)
        except Exception as e:
            return Response({
                'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': "Something went wrong",
                'status_flag': False,
                'status': "Failed",
                'error_details': str(e),
            })


class UpdateUserDetails(UpdateAPIView):
    serializer_class = UserUpdateSerializer
    authentication_classes = [TokenAuthentication]
    queryset = models.CustomUser.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Update User details API using its id"""

    def put(self, request, *args, **kwargs):
        try:
            details = models.CustomUser.objects.get(email=request.data['email'])
            if details:
                serializer = CompanyDetailSerializer(instance=details, data=request.data)
                serializer.is_valid(raise_exception=True)
                self.perform_update(serializer)
                verify_number = models.NumberVerification.objects.filter(phone_number=request.data['phone_number'])
                if not verify_number:
                    return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                     'message': 'Please validate the Phone number'})
                response_data = {'response_code': status.HTTP_200_OK,
                                 'message': "Data updated successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 'data': serializer.data}
                return Response(response_data)
            else:
                response_data = {'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "User not available",
                                 'status_flag': False,
                                 'status': "Failed",
                                 }
                return Response(response_data)
        except Exception as e:
            response_data = {'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)
                             }
            return Response(response_data)


class DeleteUser(DestroyAPIView):
    authentication_classes = [TokenAuthentication]
    queryset = models.CustomUser.objects.all()
    permission_classes = [DjangoModelPermissions]
    """API to Delete User using their id"""

    def delete(self, request, *args, **kwargs):
        try:
            user = models.CustomUser.objects.filter(email=kwargs['email']).first()
            if user:
                user.delete()
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "User has been deleted successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 })
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "User not available",
                                 'status_flag': False,
                                 'status': "Failed"})

        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)})


class AddProductRice(CreateAPIView):
    serializer_class = ProductRiceSerializer
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = [TokenAuthentication]
    queryset = models.ProductRice.objects.all()
    permission_classes = [DjangoModelPermissions]

    """API for adding rice products to the product table"""

    def post(self, request, *args, **kwargs):
        try:
            product = models.ProductRice.objects.filter(product_name=request.data['product_name']).first()
            if not product:
                serializer = ProductRiceSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                response_data = {'response_code': status.HTTP_200_OK,
                                 'message': "Product added successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 'data': serializer.data}
                return Response(response_data)
            else:
                return Response({'response_code':status.HTTP_400_BAD_REQUEST,
                                 'message':'Product already exists try updating it'})
        except Exception as e:
            response_data = {'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             }
            return Response(response_data)


class ChangeProductRice(UpdateAPIView):
    serializer_class = UpdateProductSerializer
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = [TokenAuthentication]
    queryset = models.ProductRice.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Update Product Rice API"""

    def put(self, request, *args, **kwargs):
        try:
            product = models.ProductRice.objects.filter(id=kwargs['id'])
            if product:
                serializer = ProductRiceSerializer(instance=product, data=request.data)
                serializer.is_valid(raise_exception=True)
                self.perform_update(serializer)
                response_data = {'response_code': status.HTTP_200_OK,
                                 'message': "Product updated successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 'data': serializer.data}
                return Response(response_data)
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Product not available",
                                 'status_flag': False,
                                 'status': "Failed",
                                 })
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             })


class GetProductRice(RetrieveAPIView):
    serializer_class = GetProductSerializer
    permission_classes = [AllowAny]

    """API to Get Product Rice using Product id """
    def get(self, request, *args, **kwargs):
        try:
            product = models.ProductRice.objects.filter(product_name=request.data['product_name']).first()
            if product:
                serializer = ProductRiceSerializer(instance=product)
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': serializer.data})
            else:
                return Response({'status_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Product not available"})
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             })


class GetAllProductRice(ListAPIView):
    queryset = models.ProductRice.objects.all()
    serializer_class = ProductRiceSerializer
    permission_classes = [AllowAny]

    def list(self, request, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = ProductRiceSerializer(queryset, many=True)
            return Response({'response_code': status.HTTP_200_OK,
                             'message': "List of products",
                             'status_flag': True,
                             'status': "Success",
                             'data': serializer.data
                             })
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             })


class DeleteProductRice(DestroyAPIView):
    authentication_classes = [TokenAuthentication]
    queryset = models.ProductRice.objects.all()
    permission_classes = [DjangoModelPermissions]

    """API to Delete Product Rice using Product id"""
    def delete(self, request, *args, **kwargs):
        try:
            product = models.ProductRice.objects.filter(id=kwargs['id'])
            if product:
                product.delete()
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "Product has been deleted successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 })
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Product not available",
                                 'status_flag': False,
                                 'status': "Failed"})
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)})


class AddProductPulse(CreateAPIView):
    serializer_class = ProductPulseSerializer
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = [TokenAuthentication]
    queryset = models.ProductPulses.objects.all()
    permission_classes = [DjangoModelPermissions]

    """API for adding pulse products to the product table"""

    def post(self, request, *args, **kwargs):
        try:
            product = models.ProductPulses.objects.filter(product_name=request.data['product_name'])
            if not product:
                serializer = ProductPulseSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                response_data = {'response_code': status.HTTP_200_OK,
                                 'message': "Product added successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 'data': serializer.data}
                return Response(response_data)
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Product already exists",
                                 'status_flag': False,
                                 'status': "Failed"})
        except Exception as e:
            response_data = {'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             }
            return Response(response_data)


class ChangeProductPulse(UpdateAPIView):
    serializer_class = UpdateProductSerializer
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = [TokenAuthentication]
    queryset = models.ProductPulses.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Update Product Pulse API"""
    def put(self, request, *args, **kwargs):
        try:
            product = models.ProductPulses.objects.filter(id=kwargs['id'])
            if product:
                serializer = ProductPulseSerializer(instance=product, data=request.data)
                serializer.is_valid(raise_exception=True)
                self.perform_update(serializer)
                response_data = {'response_code': status.HTTP_200_OK,
                                 'message': "Product updated successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 'data': serializer.data}
                return Response(response_data)
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Product not available",
                                 'status_flag': False,
                                 'status': "Failed"})

        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             })


class GetProductPulse(RetrieveAPIView):
    serializer_class = GetProductSerializer
    permission_classes = [AllowAny]

    """API to Get Product Pulse using Product id """
    def get(self, request, *args, **kwargs):
        try:
            product = models.ProductPulses.objects.filter(product_name=request.data['product_name']).first()
            if product:
                serializer = ProductPulseSerializer(instance=product)
                return Response({'status_code': status.HTTP_200_OK,
                                 'data': serializer.data})
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Product not available",
                                })
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             "error": str(e)
                             })


class GetAllProductPulse(ListAPIView):
    queryset = models.ProductPulses.objects.all()
    serializer_class = ProductPulseSerializer
    permission_classes = [AllowAny]

    """Get all product pulses list"""
    def list(self, request, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = ProductPulseSerializer(queryset, many=True)
            return Response({'response_code': status.HTTP_200_OK,
                             'message': "List of products",
                             'status_flag': True,
                             'status': "Success",
                             'data': serializer.data
                             })
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             })


class DeleteProductPulse(DestroyAPIView):
    authentication_classes = [TokenAuthentication]
    queryset = models.ProductPulses.objects.all()
    permission_classes = [DjangoModelPermissions]

    """API to Delete Product Pulse using Product id"""
    def delete(self, request, *args, **kwargs):
        try:
            product = models.ProductPulses.objects.filter(id=kwargs['id'])
            if product:
                product.delete()
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "Product has been deleted successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 })
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Product not available",
                                 'status_flag': False,
                                 'status': "Failed"})

        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)})


class AddCompanyDetails(CreateAPIView):
    serializer_class = CompanyDetailSerializer
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = [TokenAuthentication]
    queryset = models.VrihodhaDetails.objects.all()
    permission_classes = [DjangoModelPermissions]

    """API for adding Company Details"""

    def post(self, request, *args, **kwargs):
        try:
            company_details = models.VrihodhaDetails.objects.filter(company_mail=request.data['company_mail']).first()
            if not company_details:
                serializer = CompanyDetailSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                response_data = {'response_code': status.HTTP_200_OK,
                                 'message': "Data added successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 'data': serializer.data}
                return Response(response_data)
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': 'Enter valid details',
                                 'status': 'Failed'})
        except Exception as e:
            response_data = {'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             }
            return Response(response_data)


class UpdateCompanyDetails(UpdateAPIView):
    serializer_class = CompanyDetailsCustomSerializer
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = [TokenAuthentication]
    queryset = models.VrihodhaDetails.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Update Company details API using its id"""

    def put(self, request, *args, **kwargs):
        try:
            details = models.VrihodhaDetails.objects.filter(id=kwargs['id'])
            if details:
                serializer = CompanyDetailSerializer(instance=details, data=request.data)
                serializer.is_valid(raise_exception=True)
                self.perform_update(serializer)
                response_data = {'response_code': status.HTTP_200_OK,
                                 'message': "Data updated successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 'data': serializer.data}
                return Response(response_data)
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Data not available",
                                 'status_flag': False,
                                 'status': "Failed",
                                 })
        except Exception as e:
            response_data = {'response_code': status.HTTP_400_BAD_REQUEST,
                             'message': "Data not available",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)
                             }
            return Response(response_data)


class GetCompanyDetails(CreateAPIView):
    serializer_class = VrihodhaDetailsSerializer
    permission_classes = [AllowAny]

    """API to Get Vrihodha details using its id"""
    def post(self, request, *args, **kwargs):
        try:
            details = models.VrihodhaDetails.objects.filter(id=kwargs['id'])
            if details:
                serializer = CompanyDetailSerializer(instance=details)
                return Response({'status_code': status.HTTP_200_OK,
                                 'data': serializer.data[request.data['details']]})
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Data not available",
                                 })
        except Exception as e :
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)})


class DeleteCompanyDetails(DestroyAPIView):
    authentication_classes = [TokenAuthentication]
    queryset = models.VrihodhaDetails.objects.all()
    permission_classes = [DjangoModelPermissions]

    """API to Delete Company Details using its id"""
    def delete(self, request, *args, **kwargs):
        try:
            data = models.VrihodhaDetails.objects.filter(id=kwargs['id'])
            if data:
                data.delete()
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "Data has been deleted successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 })
            else:
                return Response({'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "Data not available",
                                 'status_flag': False,
                                 'status': "Failed"})
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)})


class AddAddress(CreateAPIView):
    serializer_class = AddAddressSerializer
    authentication_classes = [TokenAuthentication]
    queryset = models.DeliveryAddress.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Add User Address API"""
    def post(self, request, *args, **kwargs):
        try:
            user_detail = models.CustomUser.objects.filter(email=request.data['email']).first()
            if user_detail:
                if user_detail.is_staff != True and user_detail.is_superuser != True:
                    data = {'name' : request.data['name'],
                            'street': request.data['street'],
                            'zip_code': request.data['zip_code'],
                            'country': request.data['country']}

                    models.DeliveryAddress.objects.create(user_id=user_detail,address=data)

                    response_data = {'response_code': status.HTTP_200_OK,
                                     'message': "Address has been added successfully",
                                     'status_flag': True,
                                     'status': "success",
                                     'error_details': None,
                                     }
                    return Response(response_data)
                else:
                    return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                     'message': 'you are a staff'})
            else:
                response_data = {'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "User not found with the provided email",
                                 'status_flag': False,
                                 'status': "Failed",
                                 'error_details': None,
                                 }
                return Response(response_data)

        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)
                             })


class UserAddressList(ListAPIView):
    permission_classes = [AllowAny]

    """Get User Address List API"""
    def list(self, request, **kwargs):
        try:
            user_id = models.CustomUser.objects.filter(email=kwargs['email']).first()
            if user_id:
                queryset = models.DeliveryAddress.objects.filter(user_id=user_id)
                serializer = AddressListSerializer(queryset, many=True)
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "List of products",
                                 'status_flag': True,
                                 'status': "Success",
                                 'data': serializer.data
                                 })
            else:
                return Response({'status_code': status.HTTP_400_BAD_REQUEST,
                                 'message': 'email not found'})
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             })


class AddFeedback(CreateAPIView):
    serializer_class = UserFeedBackSerializer
    authentication_classes = [TokenAuthentication]
    queryset = models.UserFeedback.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Add User FeedBack API"""
    def post(self, request, *args, **kwargs):
        try:
            user_detail = models.CustomUser.objects.filter(email=request.data['email']).first()
            if user_detail:
                if user_detail.is_staff != True and user_detail.is_superuser != True:
                    models.UserFeedback.objects.create(user_id=user_detail,feedback=request.data['feedback'])

                    response_data = {'response_code': status.HTTP_200_OK,
                                     'message': "Feedback has been added successfully",
                                     'status_flag': True,
                                     'status': "success",
                                     'error_details': None,
                                     }
                    return Response(response_data)
                else:
                    return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                     'message': 'you are a staff'})
            else:
                response_data = {'response_code': status.HTTP_400_BAD_REQUEST,
                                 'message': "User not found with the provided email",
                                 'status_flag': False,
                                 'status': "Failed",
                                 'error_details': None,
                                 }
                return Response(response_data)

        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)
                             })


class UserFeedbackList(ListAPIView):
    permission_classes = [AllowAny]

    """Get User Feedback List API"""
    def list(self, request, **kwargs):
        try:
            user_id = models.CustomUser.objects.filter(email=kwargs['email']).first()
            if user_id:
                queryset = models.UserFeedback.objects.filter(user_id=user_id)
                serializer = FeedbackListSerializer(queryset, many=True)
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "List of products",
                                 'status_flag': True,
                                 'status': "Success",
                                 'data': serializer.data
                                 })
            else:
                return Response({'status_code': status.HTTP_400_BAD_REQUEST,
                                 'message': 'email not found'})
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             })


class PlaceOrderRice(GenericAPIView):
    serializer_class = OrderProductSerializer
    authentication_classes = [TokenAuthentication]
    queryset = models.OrderDetails.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Place order and update Order detals API"""
    def post(self, request, *args, **kwargs):
        try:
            user_details = models.CustomUser.objects.filter(email=request.data['email']).first()
            if not user_details:
                return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                 'message': 'Email not found'})
            else:
                product_details = models.ProductRice.objects.filter(product_name=request.data['product_name']).first()
                if not product_details:
                    return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                     'message': 'product not found'})
                else :
                    if not product_details.availability >= request.data['quantity']:
                        return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                         'message': 'Entered Quantity not available'})
                    else:
                        price = request.data['quantity'] * product_details.product_price_1kg
                        data = {'product': request.data['product_name'],
                                'quantity': request.data['quantity'],
                                'total price': price}
                        order = models.OrderDetails.objects.create(user_id=user_details, orders=data)
                        availability = product_details.availability
                        availability = availability-request.data['quantity']
                        product_details.availability = availability
                        product_details.save()
                        return Response({'status_code': status.HTTP_200_OK,
                                         'message': "Ordered successfully",
                                         'order details': data,
                                         'order id': order.id
                                         })
        except Exception as e:
            return Response({'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': 'something went wrong',
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)})


class PlaceOrderPulse(GenericAPIView):
    serializer_class = OrderProductSerializer
    authentication_classes = [TokenAuthentication]
    queryset = models.OrderDetails.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Place order and update Order detals API"""
    def post(self, request, *args, **kwargs):
        try:
            user_details = models.CustomUser.objects.filter(email=request.data['email']).first()
            if not user_details:
                return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                 'message': 'Email not found'})
            else:
                product_details = models.ProductPulses.objects.filter(product_name=request.data['product_name']).first()
                if not product_details:
                    return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                     'message': 'product not found'})
                else :
                    if not product_details.availability >= request.data['quantity']:
                        return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                         'message': 'Entered Quantity not available'})
                    else:
                        price = request.data['quantity'] * product_details.product_price_1kg
                        data = {'product': request.data['product_name'],
                                'quantity': request.data['quantity'],
                                'total price': price}
                        order = models.OrderDetails.objects.create(user_id=user_details, orders=data)
                        availability = product_details.availability
                        availability = availability-request.data['quantity']
                        product_details.availability = availability
                        product_details.save()
                        return Response({'status_code': status.HTTP_200_OK,
                                         'message': "Ordered successfully",
                                         'order details': data,
                                         'order id': order.id
                                         })
        except Exception as e:
            return Response({'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': 'something went wrong',
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)})


class UserOrderList(ListAPIView):
    permission_classes = [AllowAny]

    """Get User Order List API"""
    def list(self, request, **kwargs):
        try:
            user_id = models.CustomUser.objects.filter(email=kwargs['email']).first()
            if user_id:
                queryset = models.OrderDetails.objects.filter(user_id=user_id.id)
                serializer = OrderListSerializer(queryset, many=True)
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "List of products",
                                 'status_flag': True,
                                 'status': "Success",
                                 'data': serializer.data
                                 })
            else:
                return Response({'status_code': status.HTTP_400_BAD_REQUEST,
                                 'message': 'email not found'})
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "Something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e),
                             })


class DeleteUserOrder(DestroyAPIView):
    authentication_classes = [TokenAuthentication]
    queryset = models.OrderDetails.objects.all()
    permission_classes = [DjangoModelPermissions]

    """Delete User Order API"""
    def delete(self, request, *args, **kwargs):
        try:
            order = models.OrderDetails.objects.filter(id=kwargs['order_id']).first()
            if not order:
                return Response({'status_code':status.HTTP_400_BAD_REQUEST,
                                 'message': 'orders id not found'})
            else:
                order.delete()
                return Response({'response_code': status.HTTP_200_OK,
                                 'message': "Data has been deleted successfully",
                                 'status_flag': True,
                                 'status': "success",
                                 'error_details': None,
                                 })
        except Exception as e:
            return Response({'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'message': "something went wrong",
                             'status_flag': False,
                             'status': "Failed",
                             'error': str(e)})
