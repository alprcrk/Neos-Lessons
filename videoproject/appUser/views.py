from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from .models import *
from .models import UserInfo
from appCategory.models import *
from appMy.models import *
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import login_required
import iyzipay
import json
import requests
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

def send_activation_email(request,user):
    current_site = get_current_site(request)
    mail_subject = 'Hesabınızı Aktifleştirin'
    message = render_to_string('user/activation_email.html', {
        'user': user,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
        'domain': current_site.domain,
    })
    send_mail(mail_subject, message, settings.EMAIL_HOST_USER, [user.email])

def sendMail(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.get(email=email)
        userinfo = UserInfo.objects.get(user=user)
        subject = 'PAROLA HATIRLATMA'
        message = "Merhaba :" + userinfo.user.first_name + " " + userinfo.user.last_name +  '\nKaldığın yerden izlemeye devam etmek için PAROLAN: ' + userinfo.password
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [user.email]
        send_mail( subject, message, email_from, recipient_list )
        messages.success(request,'Şifreniz E-Posta adresinize gönderilmiştir.')
        return redirect('LoginUser')
    else:
        return render(request, 'user/sifreunutma.html')

def LoginUser(request):
    if request.user.is_authenticated:
        return redirect('ProfileUser')
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        char=False
        for char in username:
            if char=="@":
                char=True
        if username[-4:]==".com":
            try:
                user=User.objects.get(email=username)
                username=user.username
            except:
                messages.warning(request,"Email kayıtlı değil!")
                return redirect('LoginUser')

        user = authenticate(username=username,password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Hoşgeldiniz, {}".format(request.user.first_name) +" " + (request.user.last_name))
            return redirect('Abonelik')
        else:
            messages.warning(request, "Kullanıcı adı veya şifre yanlış !!")
            return redirect('LoginUser')
    return render(request, 'user/login.html')
         

def RegisterUser(request):
    if request.user.is_authenticated:
        return redirect('ProfileUser')
    cocukprofilfoto = ProfilFoto.objects.get(id=19)
    mainprofilfoto = ProfilFoto.objects.get(id=18)
    if request.method == "POST":
        name = request.POST.get("name")
        surname = request.POST.get("surname")
        username = request.POST.get("username")
        email = request.POST.get("email")
        tel = request.POST.get("tel")
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")
        birthdate = request.POST.get("birthdate")

        if password1 == password2:
            charup = False
            charnum = False

            for char in password1:
                if char.isupper():
                    charup = True
                if char.isnumeric():
                    charnum = True

            if charup and charnum and len(password1) >= 6:
                if not User.objects.filter(username=username).exists():
                    if not User.objects.filter(email=email).exists():
                        if not UserInfo.objects.filter(tel=tel).exists():
                            user = User.objects.create_user(
                                username=username,
                                password=password1,
                                first_name=name,
                                last_name=surname,
                                email=email
                            )
                            user.is_active = False
                            user.save()

                            userinfo = UserInfo(
                                user=user,
                                tel=tel,
                                dogum_tarihi=birthdate,
                                password=password1
                            )
                            userinfo.save()
                            profil = Profil(user=user, name = username, image = mainprofilfoto.image)
                            profil.save()
                            cocukprofil = Profil(user=user, name = "Çocuk", image=cocukprofilfoto.image)
                            cocukprofil.save()
                            # E-posta aktivasyonu için e-posta gönderme
                            send_activation_email(request, user)

                            messages.success(request, 'Kayıt işlemi başarıyla tamamlandı. E-postanızı kontrol ederek hesabınızı aktifleştirin.')
                            return redirect("LoginUser")

                        else:
                            messages.warning(request, "Bu telefon numarası kullanılıyor!")
                            # return redirect('RegisterUser')
                            hata = "tel"

                    else:
                        messages.warning(request, "Bu e-mail kullanılıyor!")
                        # return redirect('RegisterUser')
                        hata = "email"

                else:
                    messages.warning(request, "Bu kullanıcı adı kullanılıyor!")
                    # return redirect('RegisterUser')
                    hata = "username"

            else:
                messages.warning(request, "Şifreniz en az 6 karakterden oluşmalıdır ve içermesi gereken koşulları sağlamalıdır!")
                # return redirect('RegisterUser')
                hata = "password"

        else:
            messages.warning(request, "Şifreler aynı değil!")
            # return redirect('RegisterUser')
            hata = "password"

        context = {}
        if hata == "email":
            context.update({
                "name": name,
                "surname": surname,
                "username": username,
                "tel": tel,
                "birthdate": birthdate,
                "hata": hata,
            })
        elif hata == "username":
            context.update({
                "name": name,
                "surname": surname,
                "email": email,
                "tel": tel,
                "birthdate": birthdate,
                "hata": hata,
            })
        elif hata == "password":
            context.update({
                "name": name,
                "surname": surname,
                "username": username,
                "email": email,
                "tel": tel,
                "birthdate": birthdate,
                "hata": hata,
            })
        return render(request, 'user/register.html', context)
    context = {}
    return render(request, 'user/register.html', context)



def LogoutUser(request):
    logout(request)
    return redirect("indexPage")

def activate_account(request, uidb64, token):
    try:
        uid = force_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Hesabınız başarıyla aktifleştirildi. Giriş yapabilirsiniz.')
        return redirect('LoginUser')
    else:
        messages.error(request, 'Geçersiz aktivasyon bağlantısı.')
        return redirect('activation_failure')


@login_required(login_url="/LoginUser/")
def ProfileUser(request):
    profils = Profil.objects.filter(user=request.user)
    profilfoto = ProfilFoto.objects.all()
    if len(profils) <= 4:
            if request.method == 'POST' and request.POST.get("submit") == "profile-add":
                name=request.POST.get('profilname')
                image_id = request.POST.get("profoto")
                if image_id is None:
                    image_id = 18
                image = ProfilFoto.objects.get(id=image_id)
                profil = Profil(user=request.user,name=name,image=image.image)
                if Profil.objects.filter(user=request.user, name=name).exists():
                    messages.warning(request,"Aynı isimde zaten bir profil var.")  
                    return redirect('ProfileUser')  
                else:
                    profil.save()
                    return redirect('ProfileUser')
    elif len(profils) > 4:
        profils.last().delete()
        return redirect('ProfileUser')
    
    if request.method == 'POST' and request.POST.get('submit') == "profile-edit":
            name = request.POST.get('newname')
            profilid = request.POST.get('profilid')
            profil = profils.get(id=profilid)
            image_id = request.POST.get("newimage")
            if image_id is None:
                profil.image = profil.image
            else:
                image = ProfilFoto.objects.get(id=image_id)
                profil.image = image.image
                profil.save()
            if Profil.objects.filter(user=request.user, name=name).exists():
                return redirect('ProfileUser')  
            else:
                profil.name = name
                profil.save()
                return redirect('ProfileUser')  
    context={
        'profils':profils,
        'profilfoto':profilfoto,
    }
    return render(request, 'user/profile.html', context)

@login_required(login_url="/LoginUser/")
def ProfileEdit(request,pid):
    profil=Profil.objects.get(id=pid)
    profils = Profil.objects.filter(user=request.user)
    profilfoto = ProfilFoto.objects.all()
    
    if request.method=="POST":
        if request.POST.get("submit") == ("profileSave"):
            name = request.POST.get('name')
            spectator=request.POST.get("spectator")
            language=request.POST.get("language")
            image_id = request.POST.get("newimage")
            if image_id is None:
                profil.image = profil.image
            else:
                image = ProfilFoto.objects.get(id=image_id)
                profil.image = image.image
            profil.spectator=spectator
            profil.language=language
            profil.name=name
            profil.save()
            
    context={
        "profil":profil,
        'profilfoto':profilfoto,
        'categorys':Category.objects.all(),
        'profils':profils,
    }
    return render(request,'user/profile_edit.html',context)

@login_required(login_url="/LoginUser/")
def ProfileDel(request,pid):
    profil = Profil.objects.get(id=pid)
    profil.delete()
    return redirect('ProfileUser')

@login_required(login_url="/LoginUser/")
def Account(request,pid):
    profil=Profil.objects.get(id=pid)
    userinfo=UserInfo.objects.get(user=request.user)
    user = User.objects.get(username=request.user)
    
    submit = request.POST.get("save")
    if submit =="accountSave":
        if request.method == "POST":
            if userinfo.password==request.POST.get("password1"):
                username=request.POST.get("username-edit")
                email=request.POST.get("email-edit")
                tel=request.POST.get("tel-edit")
                dogum_tarihi=request.POST.get("dogum_tarihi")
                userinfo.user.username=username
                userinfo.user.email=email
                userinfo.tel=tel
                userinfo.dogum_tarihi=dogum_tarihi
                userinfo.user.save()
                userinfo.save()
                return redirect("/Account/"+pid)
            else:
                print("hataaaaaa")
            
                
    
    
    if request.POST.get('submit') == "edit-password":
        if request.method=="POST":
            oldpassword = request.POST.get('old-password')
            newpassword = request.POST.get('new-password')
            newpassword2 = request.POST.get('new-password1')
            
            if newpassword == newpassword2:
                charup = False
                charnum = False

                for char in newpassword:
                    if char.isupper():
                        charup = True
                    if char.isnumeric():
                        charnum = True

                if charup and charnum and len(newpassword) >= 6:
                    user.check_password(oldpassword)
                    if newpassword != " ":
                        user.set_password(newpassword)
                        user.save()
                        userinfo.password = newpassword
                        userinfo.save()
                        logout(request)
                        return redirect('LoginUser')
                    else:
                        messages.error(request,'Yeni Şifre kısmı boş bırakılamaz')
                else:
                    messages.error(request,'Yeni Şifre en az bir büyük harf içermelidir.')
                    messages.error(request,'Yeni Şifre en az bir sayı içermelidir.')
                    messages.error(request,'Yeni Şifre en az 6 karakter uzunluğunda olmalıdır.')
            else:
                messages.error(request,'Şifreler uyumsuz!!')

        return redirect('/Account/' + pid)
    
    if request.POST.get('Abonelikİptal') == "AbonelikİptalButon":
        if request.method == "POST":
            Abonelikİptal = request.POST.get('AbonelikİptalInput')
            userinfo.package = Abonelikİptal
            userinfo.save()
            logout(request)
            return redirect('indexPage')

    context ={
        "title":"Hesap Ayarları",
        "userinfo":userinfo,
        "profil":profil,
        'categorys':Category.objects.all(),
        'user':user,
    }
    return render(request, 'user/account.html',context)

@login_required(login_url="/LoginUser/")
def UserDelete(request,id):
    user = User.objects.get(id=id)
    user.delete()
    return redirect('/')

# LİSTEYE EKLEME
@login_required(login_url="/LoginUser/")
def AddList(request,pid):
    profil = Profil.objects.get(id=pid)
    mylist = Mylist.objects.filter(profil=profil)
    subcategory = Subcategory.objects.all()
    seriesvideo = SeriesVideo.objects.all()
    moviesvideo = MoviesVideo.objects.all()
    context = {
        "profil":profil,
        'categorys':Category.objects.all(),
        'mylist':mylist,
        'subcategory':subcategory,
        "seriesvideo":seriesvideo,
        "moviesvideo":moviesvideo,
    }
    return render(request, 'user/listeme_ekle.html' , context)

@login_required(login_url="/LoginUser/")
def ListDel(request,pid):
    mylist= Mylist.objects.get(id=pid)
    mylist.delete()
    return redirect('AddList',pid=mylist.profil.id)


def Abonelik(request):
    Userinfo = UserInfo.objects.get(user = request.user)
    if Userinfo.package == "" or Userinfo.package == None:
        if request.method == "POST":
            if request.POST.get('aylik') == "aylikbuton":
                aylik = request.POST.get('aylikid')
                start_package = datetime.datetime.now().strftime("%d-%m-%Y")
                Userinfo.end_package = (datetime.datetime.strptime(start_package, "%d-%m-%Y") + datetime.timedelta(days=30)).strftime("%d-%m-%Y")
                Userinfo.package = aylik
                Userinfo.save()
                return redirect('payment')
            if request.POST.get('yillik') == "yillikbuton":
                yillik = request.POST.get('yillikid')
                start_package = datetime.datetime.now().strftime("%d-%m-%Y")
                Userinfo.end_package = (datetime.datetime.strptime(start_package, "%d-%m-%Y") + datetime.timedelta(days=360)).strftime("%d-%m-%Y")
                Userinfo.package = yillik
                Userinfo.save()
                return redirect('payment')
    else:
        return redirect('ProfileUser')
    
    return render(request, 'abonelik.html')

api_key = 'sandbox-etkBOaBAec7Zh6jLDL59Gng0xJV2o1tV'
secret_key = 'sandbox-uC9ysXfBn2syo7ZMOW2ywhYoc9z9hTHh'
base_url = 'sandbox-api.iyzipay.com'

options = {
    'api_key': api_key,
    'secret_key': secret_key,
    'base_url': base_url
}
sozlukToken = list()




def payment(request):
    context = dict()

    buyer={
        'id': 'BY789',
        'name': 'John',
        'surname': 'Doe',
        'gsmNumber': '+905350000000',
        'email': 'email@email.com',
        'identityNumber': '74300864791',
        'lastLoginDate': '2015-10-05 12:43:35',
        'registrationDate': '2013-04-21 15:12:09',
        'registrationAddress': 'Nidakule Göztepe, Merdivenköy Mah. Bora Sok. No:1',
        'ip': '85.34.78.112',
        'city': 'Istanbul',
        'country': 'Turkey',
        'zipCode': '34732'
    }

    address={
        'contactName': 'Jane Doe',
        'city': 'Istanbul',
        'country': 'Turkey',
        'address': 'Nidakule Göztepe, Merdivenköy Mah. Bora Sok. No:1',
        'zipCode': '34732'
    }

    basket_items=[
        {
            'id': 'BI101',
            'name': 'Binocular',
            'category1': 'Collectibles',
            'category2': 'Accessories',
            'itemType': 'PHYSICAL',
            'price': '0.3'
        },
        {
            'id': 'BI102',
            'name': 'Game code',
            'category1': 'Game',
            'category2': 'Online Game Items',
            'itemType': 'VIRTUAL',
            'price': '0.5'
        },
        {
            'id': 'BI103',
            'name': 'Usb',
            'category1': 'Electronics',
            'category2': 'Usb / Cable',
            'itemType': 'PHYSICAL',
            'price': '0.2'
        }
    ]

    request_data={
        'locale': 'tr',
        'conversationId': '123456789',
        'price': '1',
        'paidPrice': '49.99',
        'currency': 'TRY',
        'basketId': 'B67832',
        'paymentGroup': 'PRODUCT',
        "callbackUrl": "http://localhost:8000/result/",
        "enabledInstallments": ['2', '3', '6', '9'],
        'buyer': buyer,
        'shippingAddress': address,
        'billingAddress': address,
        'basketItems': basket_items,
        # 'debitCardAllowed': True
    }

    checkout_form_initialize = iyzipay.CheckoutFormInitialize().create(request_data, options)
    page = checkout_form_initialize
    header = {'Content-Type': 'application/json'}
    content = checkout_form_initialize.read().decode('utf-8')
    json_content = json.loads(content)
    sozlukToken.append(json_content["token"])
    return HttpResponse(json_content["checkoutFormContent"])


@require_http_methods(['POST'])
@csrf_exempt
def result(request):
    context = dict()

    url = request.META.get('index')

    request_data = {
        'locale': 'tr',
        'conversationId': '123456789',
        'token': sozlukToken[0]
    }
    checkout_form_result = iyzipay.CheckoutForm().retrieve(request_data, options)
    result = checkout_form_result.read().decode('utf-8')
    sonuc = json.loads(result, object_pairs_hook=list)
    if sonuc[0][1] == 'success':
        context['success'] = 'Başarılı İŞLEMLER'
        return HttpResponseRedirect(reverse('success'), context)

    elif sonuc[0][1] == 'failure':
        context['failure'] = 'Başarısız'
        return HttpResponseRedirect(reverse('failure'), context)

    return HttpResponse(url)



def success(request):
    context = dict()
    context['success'] = 'İşlem Başarılı'
    return render(request, 'ok.html')


def fail(request):
    context = dict()
    context['fail'] = 'İşlem Başarısız'

    return render(request, 'fail.html', context)


def trt1_canli_yayin(request,cid):
    canli = CanlıVideo.objects.get(id=cid)
    context={
        'canli':canli,
    }
    return render(request, 'canli_yayin.html',context)