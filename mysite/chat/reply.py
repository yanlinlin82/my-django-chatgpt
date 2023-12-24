import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import string
import random
import struct
import socket
import os

def encrypt_msg(plain_msg, token, timestamp, msg_signature, nonce, encodingAESKey, appId, toUserName, fromUserName):
    print(f'encrypt_msg({plain_msg}, {token}, {timestamp}, {msg_signature}, {nonce}, {encodingAESKey}, {appId})')
    try:
        key = base64.b64decode(encodingAESKey + "=")
    except Exception as e:
        print('Invalid encodingAESKey!', e)
        return None

    # Assuming plain_msg and appId are strings and need to be encoded to bytes.
    plain_msg_bytes = plain_msg.encode('utf-8')
    appId_bytes = appId.encode('utf-8')

    # Pack the length of the message as bytes
    msg_length_bytes = struct.pack("I", socket.htonl(len(plain_msg_bytes)))

    # Concatenate everything as bytes
    text_bytes = msg_length_bytes + plain_msg_bytes + appId_bytes
    text = text_bytes

    # 对需要加密的明文进行填充补位
    block_size = 32
    text_length = len(text)
    amount_to_pad = block_size - (text_length % block_size)
    if amount_to_pad == 0:
        amount_to_pad = block_size
    pad = chr(amount_to_pad)
    text = text + (pad * amount_to_pad).encode('utf-8')

    # Initialize the backend and cipher
    iv = os.urandom(16)  # AES block size is 16 bytes, ensure this matches your requirement
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded message
    encrypted = encryptor.update(text) + encryptor.finalize()
    b64_encrypted = base64.b64encode(iv + encrypted).decode('utf-8')

    AES_TEXT_RESPONSE_TEMPLATE = """<xml>
<ToUserName><![CDATA[%(toUserName)s]]></ToUserName>
<FromUserName><![CDATA[%(fromUserName)s]]></FromUserName>
<CreateTime>%(CreateTime)s</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[你好]]></Content>
<Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>
<MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>
<TimeStamp>%(timestamp)s</TimeStamp>
<Nonce><![CDATA[%(nonce)s]]></Nonce>
</xml>"""
    resp_dict = {
        'toUserName'   : toUserName,
        'fromUserName' : fromUserName,
        'CreateTime'   : timestamp,
        'msg_encrypt' : b64_encrypted,
        'msg_signaturet': msg_signature,
        'timestamp'    : timestamp,
        'nonce'        : nonce,
        }
    resp_xml = AES_TEXT_RESPONSE_TEMPLATE % resp_dict
    return resp_xml

class Msg(object):
    def __init__(self):
        pass

    def send(self):
        return "success"

class TextMsg(Msg):
    def __init__(self, toUserName, fromUserName, content):
        self.__dict = dict()
        self.__dict['ToUserName'] = toUserName
        self.__dict['FromUserName'] = fromUserName
        self.__dict['CreateTime'] = int(time.time())
        self.__dict['Content'] = content

    def send(self):
        XmlForm = """
            <xml>
                <ToUserName><![CDATA[{ToUserName}]]></ToUserName>
                <FromUserName><![CDATA[{FromUserName}]]></FromUserName>
                <CreateTime>{CreateTime}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[{Content}]]></Content>
            </xml>
            """
        return XmlForm.format(**self.__dict)

class ImageMsg(Msg):
    def __init__(self, toUserName, fromUserName, mediaId):
        self.__dict = dict()
        self.__dict['ToUserName'] = toUserName
        self.__dict['FromUserName'] = fromUserName
        self.__dict['CreateTime'] = int(time.time())
        self.__dict['MediaId'] = mediaId

    def send(self):
        XmlForm = """
            <xml>
                <ToUserName><![CDATA[{ToUserName}]]></ToUserName>
                <FromUserName><![CDATA[{FromUserName}]]></FromUserName>
                <CreateTime>{CreateTime}</CreateTime>
                <MsgType><![CDATA[image]]></MsgType>
                <Image>
                <MediaId><![CDATA[{MediaId}]]></MediaId>
                </Image>
            </xml>
            """
        return XmlForm.format(**self.__dict)
