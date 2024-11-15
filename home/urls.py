from django.contrib import admin
from django.urls import path,include
from home import views

urlpatterns = [
    path('',views.index, name='home'),
    path('profile/', views.profile, name='profile'), 
    path('login',views.loginuser, name='login'),
    path('logout',views.logoutuser, name='logout'),
    path('signup', views.signupuser, name='signup'),
    path('change-password/', views.change_password, name='change_password'),
    path('forgot-password/', views.forgot_password, name='forgot_password'), 
    
]
