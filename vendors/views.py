from django.shortcuts import redirect, render,get_object_or_404

from accounts.forms import UserProfileForm
from accounts.models import UserProfile
from .models import Vendor
from .forms import VendorForm
from django.contrib import messages


# Create your views here.
def vprofile(request):
    # user = request.user
    # profile_form = UserProfileForm(instance=UserProfile.objects.get(user=user))
    # vendor_form = VendorForm(instance=Vendor.objects.get(user=user))

    # OR

    profile = get_object_or_404(UserProfile,user=request.user)
    vendor = get_object_or_404(Vendor,user=request.user) 

    if request.method == 'POST':
        profile_form = UserProfileForm(request.POST,request.FILES,instance=profile) 
        vendor_form = VendorForm(request.POST,request.FILES,instance=vendor) 
        if profile_form.is_valid() and vendor_form.is_valid():
            profile_form.save()
            vendor_form.save() 
            messages.success(request,'Settings updated.')
            return redirect('vprofile')
        else:
            print(profile_form.errors) 
            print(vendor_form.errors)
    else:
        profile_form = UserProfileForm(instance=profile)
        vendor_form = VendorForm(instance=vendor)
    context = {
        'profile_form' : profile_form,
        'vendor_form' : vendor_form,
        'profile':profile,
        'vendor':vendor
    }

    return render(request,'vendor/vprofile.html',context=context) 