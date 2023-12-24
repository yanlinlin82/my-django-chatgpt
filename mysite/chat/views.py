from django.shortcuts import render
from django.contrib import auth
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserMessageCount
from dotenv import load_dotenv
from openai import OpenAI
import os
import hashlib
import re
from . import reply
from . import receive

env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
load_dotenv(env_file)

pattern = r'@AI\b'

def is_asking_chatgpt(text):
    # text contains '@AI' (case insensitive)
    return re.search(pattern, text, flags=re.IGNORECASE)

@csrf_exempt
def wx(request):
    try:
        wx_res = WeiXinResponse(request)
        if not wx_res.check():
            return HttpResponse('') # return empty response immediately

        if request.method == 'POST':
            return wx_res.process_post(request.body)

        return HttpResponse(wx_res.echostr)
    except Exception as e:
        print(f'Exception: {e}')

    return HttpResponse('') # return empty response immediately

client = OpenAI()

def get_chatgpt_response(in_msg):
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": in_msg}]
    )
    out_msg = completion.choices[0].message.content
    return out_msg

class WeiXinResponse:
    def __init__(self, request) -> None:
        print('==========================')
        print('request = ', request)

        self.token = os.getenv('WX_TOKEN')

        self.signature = request.GET.get('signature', '')
        self.timestamp = request.GET.get('timestamp', '')
        self.nonce = request.GET.get('nonce', '')
        self.echostr = request.GET.get('echostr', '')

        self.openid = request.GET.get('openid', '')
        self.encrypt_type = request.GET.get('encrypt_type', '')
        self.msg_signature = request.GET.get('msg_signature', '')

    def check(self):
        # Build list and sort it
        data_list = [self.token, self.timestamp, self.nonce]
        data_list.sort()

        # Concatenate list and hash it
        sha1 = hashlib.sha1()
        sha1.update(''.join(data_list).encode('utf-8'))  # Update with concatenated string
        hashcode = sha1.hexdigest()

        if self.signature != hashcode:
            print(f"Unmatched signature: expected '{hashcode}', got '{self.signature}'")
        return hashcode == self.signature

    def process_post(self, web_data):
        if len(web_data) == 0:
            return HttpResponse('success') # return immediately
        print('web_data = ', web_data)

        encodingAESKey = os.getenv('WX_ENCODING_AES_KEY')
        appId = os.getenv('WX_APP_ID')
        recMsg = receive.parse_xml(web_data, self.encrypt_type, encodingAESKey, appId)

        if isinstance(recMsg, receive.Msg) and recMsg.MsgType == 'text':
            toUser = recMsg.FromUserName
            fromUser = recMsg.ToUserName
            content = recMsg.Content.decode('utf-8')
            print('content = ', content)
            if is_asking_chatgpt(content):
                content = re.sub(pattern, '', content, flags=re.IGNORECASE)
                response_msg = '（本条消息为基于AI的自动回复）\n\n' + get_chatgpt_response(content)
                print('response_msg = ', response_msg)
                replyMsg = reply.TextMsg(toUser, fromUser, response_msg)
                return HttpResponse(replyMsg.send())
            else:
                print("暂且不处理 (不带有@AI)")
                return HttpResponse("success")
        else:
            print("暂且不处理 (非文本消息)")
            return HttpResponse("success")

client = OpenAI()

def get_chatgpt_response(in_msg):
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": in_msg}]
    )
    out_msg = completion.choices[0].message.content
    return out_msg
