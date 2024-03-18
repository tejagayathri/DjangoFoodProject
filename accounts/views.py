from django.shortcuts import render,redirect
from django.http import HttpResponse

from vendors.forms import VendorForm
from .forms import UserForm
from .models import User, UserProfile
from django.contrib import messages,auth
from .utils import detectUser,send_verification_email
from django.contrib.auth.decorators import login_required,user_passes_test
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from vendors.models import Vendor

from django.core.exceptions import PermissionDenied

# Restrict the vendor accessing from the customer page
def vendor_check_role(user):
    if(user.role == 1):
        return True
    else:
        raise PermissionDenied


# Restrict the customer accessing from the vendor page
def customer_check_role(user):
    if(user.role==2):
        return True
    else:
        raise PermissionDenied

# Create your views here.

def registerUser(request):
    if(request.user.is_authenticated):
        messages.warning(request,'You are already logged in')
        return redirect('dashboard')
    elif(request.method == 'POST'): 
        print(request.POST) 
        form = UserForm(request.POST) 
        if(form.is_valid()): 
            # Create the user using the form
            # password = form.cleaned_data['password']
            # user = form.save(commit=False) 
            # user.set_password(password)
            # user.role = User.CUSTOMER
            # user.save() 

            # Create the user using create_user method 
            first_name = form.cleaned_data['first_name'] 
            last_name = form.cleaned_data['last_name'] 
            username = form.cleaned_data['username'] 
            email = form.cleaned_data['email'] 
            password = form.cleaned_data['password'] 
            user = User.objects.create_user(first_name=first_name,last_name=last_name,username=username,email=email,password=password)
            user.role = User.CUSTOMER
            user.save()

            mail_subject = 'Please activate your account'
            email_template = 'accounts/emails/account_verification_email.html'
            # send verification mail
            send_verification_email(request,user,mail_subject,email_template)

            messages.success(request,'You account has been registered successfully')
            return redirect('registerUser')
        else:
            print('Invalid Form') 
            print(form.errors) 
    else:
        form = UserForm() 
    context = { 'form' : form }
    return render(request,'accounts/registerUser.html',context)


def registerVendor(request):
    if(request.user.is_authenticated):
        messages.warning(request,'You are already logged in')
        return redirect('dashboard')
    elif(request.method=='POST'):
        form = UserForm(request.POST) 
        v_form = VendorForm(request.POST,request.FILES) 
        if(form.is_valid() and v_form.is_valid):
            first_name = form.cleaned_data['first_name'] 
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name,last_name=last_name,username=username,email=email,password=password)
            user.role = User.VENDOR
            user.save() 
            vendor = v_form.save(commit=False) 
            vendor.user = user 
            user_profile = UserProfile.objects.get(user=user)
            vendor.user_profile = user_profile
            vendor.save()

            mail_subject = 'Please activate your account'
            email_template = 'accounts/emails/account_verification_email.html'
            # send verification mail
            send_verification_email(request,user,mail_subject,email_template)

            messages.success(request,'Your account has been registered successfully! Please wait for the approval.') 
            return redirect('registerVendor')
        else:
            print('Invalid form')
            print(form.errors)
    else:
        form = UserForm() 
        v_form = VendorForm() 
    context = {
        'form' : form,
        'v_form' : v_form
    }

    return render(request,'accounts/registerVendor.html',context) 


def activate(request,uidb64,token):
    # Activate the user by setting the is_active to true
    try:
        uid = urlsafe_base64_decode(uidb64)
        user = User._default_manager.get(pk=uid) 
    except(TypeError,OverflowError,ValueError,User.DoesNotExist):
        user = None

    if(user is not None and default_token_generator.check_token(user,token)):
        user.is_active = True 
        user.save()
        messages.success(request,'Congratulations, you account is activated!')
        return redirect('myAccount')
    else:
        messages.error(request,'Invalid activation link')
        return redirect('myAccount')


def login(request):
    if(request.user.is_authenticated):
        messages.warning(request,'You are already logged in')
        return redirect('custDashboard')
    elif(request.method =='POST'):
        email = request.POST['email'] 
        password = request.POST['password'] 

        user = auth.authenticate(email=email,password=password)

        if user is not None:
            auth.login(request,user) 
            messages.success(request,'You are now logged in') 
            return redirect('custDashboard') 
        else:
            messages.error(request,'Invalid Login Credentials')
            return redirect('login')

    return render(request,'accounts/login.html')


def logout(request):
    auth.logout(request) 
    messages.info(request,'You are logged out.')
    return redirect('login') 


@login_required(login_url='login')
def myAccount(request):
    user = request.user
    redirectUrl = detectUser(user)
    return redirect(redirectUrl)


@login_required(login_url='login')
@user_passes_test(customer_check_role)
def custDashboard(request):
    return render(request,'accounts/custDashboard.html')


@login_required(login_url='login')
@user_passes_test(vendor_check_role)
def vendorDashboard(request):
    return render(request,'accounts/VendorDashboard.html')


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email) 
            mail_subject = 'Reset your password' 
            email_template = 'accounts/emails/reset_password_email.html'

            # send reset password email
            send_verification_email(request,user,mail_subject,email_template)

            messages.success(request,'Password reset link has been sent to your email address.')
            return redirect('login') 
        else:
            messages.error(request,'Account does not exist.')
            return redirect('forgot_password') 
        
    return render(request,'accounts/forgot_password.html')


def reset_password_validate(request,uidb64,token):
    # validate the user by decoding the token and user pk
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid) 
        print(user,uid)
    except(TypeError,OverflowError,ValueError,User.DoesNotExist):
        user = None
    
    if(user is not None and default_token_generator.check_token(user,token)):
        request.session['uid'] = uid
        messages.info(request, 'Please reset your password') 
        return redirect('reset_password') 
    else:
        messages.error(request,'This link has been expired!') 
        return redirect('myAccount')


def reset_password(request):

    if(request.method == 'POST'):
        password = request.POST['password'] 
        confirm_password = request.POST['confirm_password'] 

        if(password == confirm_password):
            pk = request.session.get('uid') 
            user = User.objects.get(pk=pk) 
            user.set_password(password) 
            user.is_active = True
            user.save() 
            messages.success(request,'Password reset successful')
            return redirect('login') 
        else:
            messages.error(request,'Passwords do not match!')
            return redirect('reset_password')
    return render(request,'accounts/reset_password.html')