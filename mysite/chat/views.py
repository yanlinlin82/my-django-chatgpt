from django.shortcuts import render
from django.contrib import auth
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserMessageCount
from dotenv import load_dotenv
import os
from . import weixin

env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
load_dotenv(env_file)

@csrf_exempt
def wx(request):
    try:
        wx_res = weixin.Handler(request)
        if not wx_res.check():
            return HttpResponse('') # return empty response immediately

        if request.method == 'POST':
            res = wx_res.process_post(request.body)
            return HttpResponse(res)

        return HttpResponse(wx_res.echostr)
    except Exception as e:
        print(f'Exception: {e}')

    return HttpResponse('') # return empty response immediately
