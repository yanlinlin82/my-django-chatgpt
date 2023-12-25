from django.shortcuts import render
from django.contrib import auth
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from dotenv import load_dotenv
import os
from . import weixin
import threading

env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
load_dotenv(env_file)

@csrf_exempt
def wx(request):
    try:
        thread_id = threading.get_ident()
        print(f'[{thread_id}]=============> wx request: {request}')
        wx_res = weixin.Handler()
        res = wx_res.process_post(request)
        print(f'[{thread_id}]=============> wx returns: {res}')
        return HttpResponse(res)
    except Exception as e:
        print(f'Exception: {e}')

    return HttpResponse('') # return empty response immediately
