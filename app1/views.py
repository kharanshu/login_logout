from django import forms
from django.contrib import messages
from django.contrib.auth import (authenticate, login, logout,
                                 update_session_auth_hash)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (PasswordChangeForm, SetPasswordForm,
                                       UserCreationForm)
from django.contrib.auth.models import User
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
    #entries = Entry.objects.filter(created_by=request.user)
    entries = Entry.objects.all()
    print(entries)
    return render(request, 'welcome.html', context={'entries': entries})

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
        entry.created_by = new_user
        entry.save()
        return redirect('welcome')

    return render(request, 'transfer.html', context = {'entry': entry})

