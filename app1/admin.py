from django.contrib import admin
from django.contrib.sessions.models import Session
from .models import Entry
# Register your models here.

admin.site.register([Entry, Session])