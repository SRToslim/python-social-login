import os
from urllib.parse import urlencode

import requests
from django.contrib.auth import authenticate, login
from django.core.files.base import ContentFile
from django.shortcuts import redirect

from helpbazar import settings
from userauth.models import User, Profile
from userauth.utils import get_client_ip, get_client_os_info, get_client_browser_info, get_client_device_info


def google_login(request):
    client_id = settings.GOOGLE_AUTH_KEY
    redirect_uri = settings.GOOGLE_AUTH_REDIRECT_URI
    scope = 'https://www.googleapis.com/auth/userinfo.email'

    auth_url = 'https://accounts.google.com/o/oauth2/auth?' + urlencode({
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'response_type': 'code',
    })
    return redirect(auth_url)


def google_callback(request):
    if 'code' in request.GET:
        code = request.GET['code']
        client_id = settings.GOOGLE_AUTH_KEY
        client_secret = settings.GOOGLE_AUTH_SECRET
        redirect_uri = settings.GOOGLE_AUTH_REDIRECT_URI

        token_url = 'https://accounts.google.com/o/oauth2/token'
        payload = {
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }
        response = requests.post(token_url, data=payload)
        token_data = response.json()

        user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
        headers = {'Authorization': f'Bearer {token_data["access_token"]}'}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info = user_info_response.json()

        print(user_info)

        user = authenticate(request, google_user_info=user_info)

        if user:
            user.social_id = user_info['sub']
            user.social_provider = 'Google'
            user.last_ip = get_client_ip(request)
            user.client_os_info = get_client_os_info(request)
            user.client_browser_info = get_client_browser_info(request)
            user.get_client_device_info = get_client_device_info(request)
            user.is_online = True
            user.save()

            profile, created = Profile.objects.update_or_create(user=user)

            if 'picture' in user_info:
                picture_url = user_info['picture']
                try:
                    response = requests.get(picture_url)
                    response.raise_for_status()
                    image_data = response.content

                    image_name = os.path.basename(picture_url)

                    profile.image.save(image_name, ContentFile(image_data), save=True)
                except Exception as e:
                    print(f"Error fetching or saving image from URL: {str(e)}")
            profile.save()

            login(request, user)

            return redirect('index')
        else:
            user = User(username=user_info['email'], email=user_info['email'], social_id=user_info['sub'],
                        social_provider='Google')
            user.is_active = True
            user.is_verify = True
            user.is_online = True
            user.ip = get_client_ip(request)
            user.client_os_info = get_client_os_info(request)
            user.client_browser_info = get_client_browser_info(request)
            user.get_client_device_info = get_client_device_info(request)
            user.save()

            profile = Profile.objects.create(user=user)

            if 'picture' in user_info:
                picture_url = user_info['picture']
                try:
                    response = requests.get(picture_url)
                    response.raise_for_status()
                    image_data = response.content

                    image_name = os.path.basename(picture_url)

                    profile.image.save(image_name, ContentFile(image_data), save=True)
                except Exception as e:
                    print(f"Error fetching or saving image from URL: {str(e)}")
            profile.save()

            login(request, user)
            return redirect('index')


def facebook_login(request):
    facebook_auth_url = 'https://www.facebook.com/v17.0/dialog/oauth'
    redirect_uri = settings.FACEBOOK_REDIRECT_URI
    client_id = settings.FACEBOOK_APP_ID

    return redirect(f'{facebook_auth_url}?client_id={client_id}&redirect_uri={redirect_uri}&scope=email')


def facebook_callback(request):
    code = request.GET.get('code')
    redirect_uri = settings.FACEBOOK_REDIRECT_URI

    token_url = f'https://graph.facebook.com/v17.0/oauth/access_token?client_id={settings.FACEBOOK_APP_ID}&redirect_uri={redirect_uri}&client_secret={settings.FACEBOOK_APP_SECRET}&code={code}'
    response = requests.get(token_url)
    token_data = response.json()

    access_token = token_data.get('access_token')

    user_data_url = f'https://graph.facebook.com/v17.0/me?fields=id,name,email,gender,picture&access_token={access_token}'
    response = requests.get(user_data_url)
    user_data = response.json()

    user = authenticate(request, facebook_user_info=user_data)

    if user:
        user.social_id = user_data['id']
        user.social_provider = 'Facebook'
        user.last_ip = get_client_ip(request)
        user.client_os_info = get_client_os_info(request)
        user.client_browser_info = get_client_browser_info(request)
        user.get_client_device_info = get_client_device_info(request)
        user.is_online = True
        user.save()
        profile, created = Profile.objects.get_or_create(user=user)
        profile.full_name = user_data['name']

        if 'picture' in user_data and 'data' in user_data['picture']:
            picture_url = user_data['picture']['data']['url']
            try:
                response = requests.get(picture_url)
                response.raise_for_status()
                image_data = response.content

                image_name = os.path.basename(picture_url)

                profile.image.save(image_name, ContentFile(image_data), save=True)
            except Exception as e:
                print(f"Error fetching or saving image from URL: {str(e)}")

        if 'gender' in user_data:
            profile.gender = user_data['gender']

        profile.save()
        login(request, user)
        return redirect('index')
    else:
        user = User(username=user_data['email'], email=user_data['email'], social_id=user_data['id'],
                    social_provider='Facebook')
        user.is_active = True
        user.is_verify = True
        user.is_online = True
        user.ip = get_client_ip(request)
        user.client_os_info = get_client_os_info(request)
        user.client_browser_info = get_client_browser_info(request)
        user.get_client_device_info = get_client_device_info(request)
        user.save()

        profile = Profile.objects.create(user=user, full_name=user_data['name'])

        if 'picture' in user_data and 'data' in user_data['picture']:
            picture_url = user_data['picture']['data']['url']
            try:
                response = requests.get(picture_url)
                response.raise_for_status()
                image_data = response.content

                image_name = os.path.basename(picture_url)

                profile.image.save(image_name, ContentFile(image_data), save=True)
            except Exception as e:
                print(f"Error fetching or saving image from URL: {str(e)}")

        if 'gender' in user_data:
            profile.gender = user_data['gender']

        profile.save()
        login(request, user)
        return redirect('index')


def github_login(request):
    github_oauth_url = f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}&redirect_uri={settings.GITHUB_REDIRECT_URI}&scope=user"
    return redirect(github_oauth_url)


def github_callback(request):
    code = request.GET.get("code")

    response = requests.post(
        "https://github.com/login/oauth/access_token",
        data={
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "code": code,
        },
        headers={"Accept": "application/json"},
    )
    data = response.json()
    github_token = data.get("access_token")

    if github_token:
        user_data_response = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {github_token}"},
        )
        user_data = user_data_response.json()

        user = authenticate(request, github_user_info=user_data)

        if user:
            user.social_id = user_data['id']
            user.social_provider = 'Github'
            user.last_ip = get_client_ip(request)
            user.client_os_info = get_client_os_info(request)
            user.client_browser_info = get_client_browser_info(request)
            user.get_client_device_info = get_client_device_info(request)
            user.is_online = True
            user.save()
            profile, created = Profile.objects.get_or_create(user=user)
            profile.full_name = user_data.get('name') or user_data.get('login')
            if 'avatar_url' in user_data:
                avatar_url = user_data['avatar_url']
                try:
                    response = requests.get(avatar_url)
                    response.raise_for_status()
                    image_data = response.content

                    image_name = os.path.basename(avatar_url)

                    profile.image.save(image_name, ContentFile(image_data), save=True)
                except Exception as e:
                    print(f"Error fetching or saving image from URL: {str(e)}")
            profile.save()
            login(request, user)
            return redirect('index')
        else:
            user = User(username=user_data['email'], email=user_data['email'], social_id=user_data['id'],
                        social_provider='Github')
            user.is_active = True
            user.is_verify = True
            user.is_online = True
            user.ip = get_client_ip(request)
            user.client_os_info = get_client_os_info(request)
            user.client_browser_info = get_client_browser_info(request)
            user.get_client_device_info = get_client_device_info(request)
            user.save()
            profile = Profile.objects.create(user=user)
            profile.full_name = user_data.get('name') or user_data.get('login')
            if 'avatar_url' in user_data:
                avatar_url = user_data['avatar_url']
                try:
                    response = requests.get(avatar_url)
                    response.raise_for_status()
                    image_data = response.content

                    image_name = os.path.basename(avatar_url)

                    profile.image.save(image_name, ContentFile(image_data), save=True)
                except Exception as e:
                    print(f"Error fetching or saving image from URL: {str(e)}")
            profile.save()
            login(request, user)
            return redirect('index')
