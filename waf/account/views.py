from django.shortcuts import render
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render,redirect
from .forms import LoginForm
from django.contrib.auth import authenticate,login,logout
from .forms import RegisterForm
from django.contrib.auth.models import User



#REGISTER
def register(request):
    if request.method=='POST':
        form=RegisterForm(request.POST)

        if form.is_valid():
            form.save()
            messages.success(request,"Qeydiyyatınız uğurla tamamlanmışdır.")
            return redirect('login')
            
    else:
        form=RegisterForm
            
    return render(request,'account/register.html',{'form':form})





#LOGIN
def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username,
                                        password=password)

            if user is not None:
                if user.is_active:
                    login(request,user)
                    return redirect('attack_info')

                else:
                    messages.info(request, 'Disabled Account')

            else:
                messages.info(request, 'Check Your Username and Password')

    else:
        form = LoginForm()

    return render(request, 'account/login.html', {'form':form})



