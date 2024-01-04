from django.urls import path
from .views import *

urlpatterns = [
    path('User/user-register/', UserRegister.as_view()),
    path('User/user-login/',UserLogin.as_view()),
    path('User/update-user-details/',UpdateUserDetails.as_view()),
    path('User/delete-user/',DeleteUser.as_view()),

    path('otp/generate-otp/', NumberVerify.as_view()),
    path('otp/verify-otp/', OtpVerification.as_view()),

    path('ProductRice/add-rice/', AddProductRice.as_view()),
    path('ProductRice/update-rice/<int:id>', ChangeProductRice.as_view()),
    path('ProductRice/get-rice/', GetProductRice.as_view()),
    path('ProductRice/get-product-list',GetAllProductRice.as_view()),
    path('ProductRice/delete-rice/<int:id>', DeleteProductRice.as_view()),

    path('ProductPulse/add-pulse/', AddProductPulse.as_view()),
    path('ProductPulse/update-pulse/<int:id>', ChangeProductPulse.as_view()),
    path('ProductPulse/get-pulse/', GetProductPulse.as_view()),
    path('ProductPulse/get-product-list',GetAllProductPulse.as_view()),
    path('ProductPulse/delete-pulse/<int:id>', DeleteProductPulse.as_view()),

    path('CompanyDetails/add-company-details/', AddCompanyDetails.as_view()),
    path('CompanyDetails/update-company-details/<int:id>',UpdateCompanyDetails.as_view()),
    path('CompanyDetails/get-company-details/<int:id>',GetCompanyDetails.as_view()),
    path('CompanyDetails/delete-company-details/<int:id>',DeleteCompanyDetails.as_view()),

    path('Orders/place-order-rice/',PlaceOrderRice.as_view()),
    path('Orders/place-order-pulse/',PlaceOrderPulse.as_view()),
    path('Orders/order-history/<str:email>',UserOrderList.as_view()),
    path('Orders/delete-order/<int:order_id>',DeleteUserOrder.as_view()),

    path('FeedBack/add-feedback/',AddFeedback.as_view()),
    path('FeedBack/get-feedback-list/<str:email>',UserFeedbackList.as_view()),

    path('Address/add-Address/',AddAddress.as_view()),
    path('Address/user-address-list/<str:email>',UserAddressList.as_view()),

]