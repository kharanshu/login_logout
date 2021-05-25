from .models import Entry
from django.core.exceptions import PermissionDenied
from django.shortcuts import  redirect
import time

def check_entry_by_user(func):
    def inner(request, *args, **kwargs):
        entr_obj = Entry.objects.get(id=kwargs['id'])
        if entr_obj.created_by == request.user:
           return func(request, *args, **kwargs)  # edit
        else:
            raise PermissionDenied
    return inner


# superuser

def superuser_only(func):
    '''Limit view to superuser only'''

    def inner(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied

        else:
            return func(request, *args, **kwargs)
    return inner

# Time it decorator

def time_it(func):
    def inner(request, *args, **kwargs):
        ts = time.time()
        result = func(request, *args, **kwargs)
        te = time.time()
        print('time taken for the view is:- ', ts-te)
        return result
    return inner



