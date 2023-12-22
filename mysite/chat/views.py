from django.shortcuts import render
from django.contrib import auth
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserMessageCount
from dotenv import load_dotenv
from openai import OpenAI
import os

env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
load_dotenv(env_file)

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
