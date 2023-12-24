from django.shortcuts import render
from django.contrib import auth
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserMessageCount
from dotenv import load_dotenv
from openai import OpenAI
import os
import hashlib
import re
from . import reply
from . import receive
import xml.etree.ElementTree as ET

env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
load_dotenv(env_file)

def contains_at_ai(text):
    # Define the pattern: look for '@AI' surrounded by word boundaries
    pattern = r'@AI\b'
    
    # Use re.search to find the pattern in the text
    if re.search(pattern, text, re.IGNORECASE):  # re.IGNORECASE is used to make the search case-insensitive
        return True
    else:
        return False

@csrf_exempt
def wx(request):
    try:
        print('==========================')
        print('request = ', request)

        # Get data from request
        signature = request.GET.get('signature', '')
        timestamp = request.GET.get('timestamp', '')
        nonce = request.GET.get('nonce', '')
        echostr = request.GET.get('echostr', '')
        token = os.getenv('WX_TOKEN')

        # other data
        openid = request.GET.get('openid', '')
        encrypt_type = request.GET.get('encrypt_type', '')
        msg_signature = request.GET.get('msg_signature', '')

        # Build list and sort it
        data_list = [token, timestamp, nonce]
        data_list.sort()

        # Concatenate list and hash it
        sha1 = hashlib.sha1()
        sha1.update(''.join(data_list).encode('utf-8'))  # Update with concatenated string
        hashcode = sha1.hexdigest()

        # Debugging print: Use logging in production
        print(f"handle/GET func: hashcode, signature: {hashcode}, {signature}")

        if request.method == 'POST':
            web_data = request.body
            if len(web_data) == 0:
                print('web_data is empty')
                return HttpResponse("success")
            print('web_data = ', web_data)

            encodingAESKey = os.getenv('WX_ENCODING_AES_KEY')
            appId = os.getenv('WX_APP_ID')
            recMsg = receive.parse_xml(web_data, encrypt_type, encodingAESKey, appId)

            if isinstance(recMsg, receive.Msg) and recMsg.MsgType == 'text':
                toUser = recMsg.FromUserName
                fromUser = recMsg.ToUserName
                content = recMsg.Content.decode('utf-8')
                print('content = ', content)
                if contains_at_ai(content):
                    content = content.replace('@AI', '')
                    response_msg = '（本条消息为基于AI的自动回复）\n\n' + get_chatgpt_response(content)
                    #response_msg = '（本条消息为基于AI的自动回复）\n\n' + content
                    print('response_msg = ', response_msg)
                    replyMsg = reply.TextMsg(toUser, fromUser, response_msg)
                    return HttpResponse(replyMsg.send())
                    #if encrypt_type == 'aes':
                    #    replyText = reply.encrypt_msg(replyMsg.send(), token, timestamp, msg_signature, nonce, encodingAESKey, appId, toUser, fromUser)
                    #    print(f'replyText (encrypted) = "{replyText}"')
                    #    print('---------------')
                    #    m = receive.parse_xml(replyText.encode('utf-8'), encrypt_type, encodingAESKey, appId)
                    #    print('------------------, m.Content = ', m.Content.decode('utf-8'))
                    #    return HttpResponse(replyText)
                    #else:
                    #    return HttpResponse(replyMsg.send())
                else:
                    print("暂且不处理 (不带有@AI)")
                    return HttpResponse("success")
            else:
                print("暂且不处理 (非文本消息)")
                return HttpResponse("success")

        else:
            # Validate and return echostr
            if hashcode == signature:
                return HttpResponse(echostr)
            else:
                return HttpResponse("")

    except Exception as e:
        # Properly log errors in production
        print(e)
        return HttpResponse(str(e))

client = OpenAI()

@csrf_exempt
def login(request):
    user = request.POST.get('user')
    auth.login(request, user)
    return JsonResponse({'success': True})

@csrf_exempt
def say(request):
    #user = request.user
    #if not user.is_authenticated:
    #    return JsonResponse({'error': 'Authentication required'}, status=401)

    #user_message_count, _ = UserMessageCount.objects.get_or_create(user=user)

    #if not user_message_count.can_send_message():
    #    return JsonResponse({'error': 'Message limit reached'}, status=403)

    incoming_msg = request.POST.get('message')
    if not incoming_msg:
        return JsonResponse({'error': 'Message required'}, status=400)
    response_msg = get_chatgpt_response(incoming_msg)

    #user_message_count.increment_message_count()

    return JsonResponse({'response': response_msg})

def get_chatgpt_response(message):
    # Add your code to send the message to OpenAI's API and get a response
    # Ensure you have your OpenAI API key configured
    # ...
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            #{"role": "system", "content": "You are a poetic assistant, skilled in explaining complex programming concepts with creative flair."},
            #{"role": "user", "content": "Compose a poem that explains the concept of recursion in programming."}
            {"role": "user", "content": message}
        ]
    )

    print(completion.choices[0].message)
    return completion.choices[0].message.content
