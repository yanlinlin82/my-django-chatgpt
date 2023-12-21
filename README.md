# My Django ChatGPT

## Preparation

```sh
python -m venv chatgpt-venv/
. chatgpt-venv/bin/activate
pip install django
pip install openai
pip install socksio # allow to use proxy
```

Prepare `.env`:

```txt
OPENAI_API_KEY=xxxxxx
ALL_PROXY=socks5://host:port
```
