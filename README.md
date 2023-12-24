# My Django ChatGPT

## Preparation

```sh
python -m venv chatgpt-venv/
. chatgpt-venv/bin/activate
pip install django
pip install openai
pip install socksio # allow to use proxy
pip install python-dotenv
pip install cryptography
```

Prepare `.env`:

```txt
OPENAI_API_KEY=xxxxxx
ALL_PROXY=socks5://host:port
WX_TOKEN=xxxxx
WX_ENCODING_AES_KEY=xxxxx
WX_APP_ID=xxxxx
```

## Debug

Take remote server 'yanlinlin.cn' as an example.

```sh
# map local 8000 port to remote 8001 port
ssh -nNT -R *:8001:localhost:8000 yanlinlin.cn
```

Remote Apache configure (deploy to https://yanlinlin.cn/gpt/):

```txt
# Production
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ...
    WSGIApplicationGroup %{GLOBAL}
    WSGIDaemonProcess django_app python-home=/var/www/my-django-chatgpt/chatgpt-venv python-path=/var/www/my-django-chatgpt /mysite
    WSGIProcessGroup django_app
    WSGIScriptAlias /gpt /var/www/my-django-chatgpt/mysite/mysite/wsgi.py process-group=django_app
    <Directory /var/www/my-django-chatgpt/mysite/mysite>
        <Files wsgi.py>
            Require all granted
        </Files>
    </Directory>
</VirtualHost>
</IfModule>
```

Or:

```txt
# Development
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ...
    ProxyPass /gpt http://127.0.0.1:8001/
    ProxyPassReverse /gpt http://127.0.0.1:8001/
</VirtualHost>
</IfModule>
```
