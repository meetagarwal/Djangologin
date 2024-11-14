from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import logout,login
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.core.mail import send_mail

# Create your views here.
def index(request):
    if request.user.is_anonymous:
        return redirect("/login")
    return render(request,'index.html')

def profile(request):
    return render(request, 'profile.html', {'user': request.user})

def loginuser(request):
    if request.method=="POST":
        username=request.POST.get("username")
        password=request.POST.get("password")
       #check
        
        user = authenticate( username=username, password=password)
        if user is not None:
            login(request,user)
            return redirect("/")
        # Redirect to a success page.
        else:
            messages.error(request, 'Invalid username or password')
            return render(request,'login.html',{'error': 'Invalid username or password'})
    return render(request,'login.html')

from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render, redirect

def signupuser(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'signup.html')

        # Check if the username already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return render(request, 'signup.html')

        # Check if the password meets requirements
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters.")
            return render(request, 'signup.html')

        if password.isdigit():
            messages.error(request, "Password cannot be entirely numeric.")
            return render(request, 'signup.html')

        common_passwords = ["password", "123456", "qwerty", "abc123"]
        if password.lower() in common_passwords:
            messages.error(request, "Password is too common.")
            return render(request, 'signup.html')

        # Create the new user with hashed password
        try:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()

            # Debugging step: Check if the user is saved
            print(f"User created successfully: {user.username}")

            # Log the user in after successful registration
            login(request, user)

            # Redirect to the home page
            return redirect("/")
        except Exception as e:
            messages.error(request, f"Error creating user: {str(e)}")
            return render(request, 'signup.html')

    return render(request, 'signup.html')

def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()  # Save the new password
            update_session_auth_hash(request, form.user)  # Keep the user logged in
            messages.success(request, 'Your password was successfully updated!')
            return redirect('home')  # Redirect to home or any other page
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'change_password.html', {'form': form})




def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            # You can add your logic to create a reset link (but not implementing the form to change the password itself)
            # Just sending a generic message to the user.
            reset_link = "http://127.0.0.1:8000/reset-password"  # You can use a custom URL here for the reset password page if needed
            
            # Send the email with reset link
            email_subject = 'Password Reset Request'
            email_message = f'Click the following link to reset your password: {reset_link}'
            send_mail(email_subject, email_message, 'your-email@gmail.com', [email])

            messages.success(request, 'Password reset link sent to your email!')
            return redirect('login')  # Redirecting to login page or wherever you want
        except User.DoesNotExist:
            messages.error(request, 'No user found with that email address.')
    return render(request, 'forgot_password.html')

def logoutuser(request):
   logout(request)
   return redirect("/login")