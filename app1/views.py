from django import forms
from django.contrib import messages
from django.contrib.auth import (authenticate, login, logout,
                                 update_session_auth_hash)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (PasswordChangeForm, SetPasswordForm,
                                       UserChangeForm, UserCreationForm)
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from .decorators import check_entry_by_user, superuser_only, time_it
from .forms import EntryForm
from .models import Entry

# Create your views here.

def user_login(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            print("In Post Method...!!!")
            usern = request.POST.get("uname")
            pswd = request.POST.get("pswd")
            user_obj = authenticate(username=usern, password=pswd)
            if user_obj:
                login(request,user_obj)
                return redirect('welcome')
            return HttpResponse('Invalid Credentials...!!!')
        return render(request, 'login.html')
    else:
        return redirect('welcome')

def user_logout(request):
    logout(request)
    return redirect('login')

@login_required
def welcome_func(request):
    entries = Entry.objects.filter(created_by_id=request.user)
    #entries = Entry.objects.all()
    print(entries)
    return render(request, 'welcome.html', context={'entries': entries})

class UserSignupForm(UserCreationForm):
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text="Enter the same password as before, for verification.",
    )
    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email")

def signup(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "User Profile Created Successfully...!!!")
            return redirect('login')
        else:
            return render(request, 'signup.html', {"form":form})
    user_form =UserCreationForm()
    return render(request, 'signup.html', {"form":user_form})

@login_required
def change_password_with_old(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)

        if form.is_valid():
            user = form.save()
            # update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            # print(request.session)
            return redirect('change_password_with_old')

        else:
            return render(request, 'change_pass_with_old.html', {"form": form})
    change_form = PasswordChangeForm(request.user)
    return render(request, 'change_pass_with_old.html', {'form': change_form})

@login_required
def change_password(request):
    change_form = SetPasswordForm(request.user)
    return render(request, 'change_pass.html', {'form': change_form})

class UserProfileChangeForm(UserChangeForm):
    password = None
    class Meta:
        model = User
        # fields = '__all__'
        exclude = ('password', 'groups', 'user_permissions') 


class UserProfileChangeForm(UserChangeForm):
    password = None
    class Meta:
        model = User
        # fields = '__all__'
        exclude = ('password', 'groups', 'user_permissions') 

class AdminChangeForm(UserChangeForm):
    password = None
    class Meta:
        model = User
        # fields = '__all__'
        exclude = ('password', 'groups', 'user_permissions') 

def user_profile(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            if request.user.is_superuser:
                fm = AdminChangeForm(request.POST, instance=request.user)
            else:
                fm = UserProfileChangeForm(request.POST, instance=request.user)
            if fm.is_valid():
                fm.save()
                return redirect('user_profile')
            return render(request, 'profile.html', {"form": fm})

        if request.user.is_superuser:
            fm = AdminChangeForm(instance=request.user)
            all_users = User.objects.filter(is_active=1)

        else:
            fm = UserProfileChangeForm(instance=request.user)
            all_users = None

        return render(request, 'profile.html', {"form": fm, "users": all_users})

    else:
        raise PermissionDenied

def user_details(request, id):
    if request.user.is_authenticated:
        user_object = User.objects.get(id=id)

        if request.method == 'POST':
            fm = UserProfileChangeForm(request.POST, instance=user_object)
            if fm.is_valid():
                fm.save()
                return redirect('user_profile')

        fm = UserProfileChangeForm(instance=user_object)
        all_users = User.objects.filter(is_active=1)
        
        return render(request, 'profile.html', {"form": fm, "users": all_users})
    else:
        raise PermissionDenied

@login_required
def add_entry(request):
    if request.method == 'POST':
        form = EntryForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('welcome')
        else:
            return render(request, 'entry.html', context = {'form': form})

    ef = EntryForm()
    return render(request, 'entry.html', context={'form': ef})

@login_required
@check_entry_by_user
def edit(request, id):
    """for editing blog"""
    entry = get_object_or_404(Entry, pk=id)
    print(entry)
    if request.method == 'POST':
        fm = EntryForm(request.POST, instance=entry)
        if fm.is_valid():
            fm.save()
            return redirect(to='welcome')
    form = EntryForm(instance=entry)
    return render(request, 'entry.html', {'form': form })

@login_required
@check_entry_by_user
def remove(request, id):
    entry = get_object_or_404(Entry, pk=id)
    entry.delete()
    messages.success(request, 'Entry was successfully removed!')
    return redirect('welcome')

@login_required
@check_entry_by_user
@time_it
@superuser_only
def transfer_user(request, id):
    entry = get_object_or_404(Entry, pk=id)
    print(request.POST)
    if request.method == 'POST':
        transfer_user = request.POST.get('transfer_to')
        print(transfer_user)
        new_user = User.objects.get(username=transfer_user)
        print(new_user)
        entry.created_by_id = new_user
        entry.save()
        messages.success(request, 'Entry was successfully transferred!')
        return redirect('welcome')

    return render(request, 'transfer.html', context = {'entry': entry})

