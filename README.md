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
```

## Debug

```sh
ssh -nNT -R *:8001:localhost:8000 yanlinlin.cn
```
