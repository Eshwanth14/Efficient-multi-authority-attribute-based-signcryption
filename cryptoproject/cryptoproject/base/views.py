from django.shortcuts import render, redirect
from .forms import UserCreationForm
from django.contrib.auth import authenticate, login, logout
from .models import Account, FileHandler
import requests
import uuid
from django.http import HttpResponse
from algorithm import encryptor, decryptor
import os
from django.core.mail import send_mail
# Create your views here.

def home(request):
    return render(request, 'home.html')


def user_register(request):
    context = {}
    form = UserCreationForm()
    context['form'] = form
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            name = user.username
            email = user.email
            public_key = uuid.uuid4()
            new_user =Account(user = user, public_key = public_key)
            new_user.save()
            with open(f'media/auth_key/{name}_auth_key', 'w') as f:
                f.write(str(public_key))
            #Now lets save into the 3rd party server
            trd_prty = requests.post('http://localhost:8001/api/basic/', data = {'user':name, 'auth_token': public_key})
            res = trd_prty.json()
            if res['status'] == 'user added':
                login(request, user)
                send_auth_token(email, public_key)
                return redirect('encrypt')
            elif res['status'] == 'error':
                context['message'] = 'There was an error on third party server'
                return render(request, 'error_page.html', context)
    return render(request, 'user_register.html', context)

def user_login(request):
    context = {}
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
        return redirect('auther')
    return render(request, 'user_login.html', context)

def two_factor_authenticate(request):
    context={}
    if request.method == 'POST':
        auth_token = request.POST['auth_token']
        username = request.user.username
        trd_prt = requests.get(f'http://localhost:8001/api/basic/{username}/{auth_token}')
        res = trd_prt.json()
        if res['status'] == 'verified':
            return redirect('encrypt')
        elif res['status'] == 'not verified':
            context['message'] = 'User Not Verified'
            return render(request, 'error_page.html', context)
        elif res['status'] == 'User not found':
            context['message'] = 'There is an issue in 3rd party server, We cant found any user with this credential'
            return render(request, 'error_page.html',context)
    return render(request, 'tfa.html')

def user_logout(request):
    logout(request)
    return redirect('home')

def view_public_key(request):
    context = {}
    if request.user.is_authenticated:
        instance = Account.objects.get(user = request.user)
        name = request.user.username
        context['public_key'] = f'/media/auth_key/{name}_auth_key'
        pub_key = instance.public_key
        context['pub_key'] = pub_key
        return render(request, 'view_public_key.html', context)
    else:
        context['message'] = 'You are not Authenticated to enter the access this page'
        return render(request, 'error_page.html', context)


def upload_and_encrypt(request):
    context = {}
    if request.user.is_authenticated:
        if request.method == 'POST':
            filename = request.POST['filename']
            file = request.FILES['file']
            normalfile = file.read()
            with open(f'media/non_enc_files/{filename}', 'wb') as f:
                f.write(normalfile)
            file_path = f'media/non_enc_files/{filename}'
            encrypted_file_path =encryptor.encryption(file_path)
            user = request.user
            account_instance = Account.objects.get(user=user)
            file_dets = FileHandler(user=account_instance, filename=filename, encrypted_file_path=encrypted_file_path)
            file_dets.save()
            context['enc'] = encrypted_file_path
            return render(request, 'encrypt.html', context)
        return render(request, 'encrypt.html', context)
    else:
        context['message'] = 'You are not Authenticated to enter the access this page'
        return render(request, 'error_page.html', context)

def list_of_encrypted_file(request):
    context = {}
    if request.user.is_authenticated:
        user = request.user
        account_instance = Account.objects.get(user = user)
        all_file_dets = FileHandler.objects.filter(user = account_instance)
        context['all_files'] = all_file_dets
        return render(request, 'list_files.html', context)
    else:
        context['message'] = 'You are not authenticated cant fetch any list for you, Please go back to previous page.'
        return render(request, 'error_page.html', context)

def decrypt_file(request, filename):

    file_dets = FileHandler.objects.get(filename=filename)
    context = {}
    if request.user.is_authenticated:
        if request.method == 'POST':
            fernet_key = request.FILES['fer_key']
            file_path = file_dets.encrypted_file_path
            filename = file_dets.filename
            try:
                decryptor.decryption(filename, fernet_key)
            except:
                context['message'] = 'Error while Decrypting. Check if you used the correct key'
                return render(request, 'error_page.html', context)
            context['file_path'] = '/' + f'media/temp/{filename}'
            FileHandler.objects.get(filename=filename).delete()

            return render(request, 'decrypt.html', context)
            
        return render(request, 'decrypt.html', context)
    else:
        context['message'] = 'You are not Authenticated to enter the access this page'
        return render(request, 'error_page.html', context)

def navigator(request):
    return render(request, 'move_to_login.html')
   
def send_auth_token(email, auth_token):
    subject = '2FA key'
    message = f'The 2FA key for your account is {auth_token}'
    from_email = 'a19104019@gmail.com'
    print(message)
    send_mail(subject, message, from_email, [email])
