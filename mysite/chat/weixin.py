import os
import re
import hashlib
from openai import OpenAI
import base64
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct
import socket
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import struct
import socket
import os

pattern = r'@AI\b'

class Handler:
    def __init__(self, request) -> None:
        self.client = OpenAI()

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
            return ''
        print('web_data = ', web_data)

        encodingAESKey = os.getenv('WX_ENCODING_AES_KEY')
        appId = os.getenv('WX_APP_ID')
        recMsg = self.parse_xml(web_data, self.encrypt_type, encodingAESKey, appId)

        if isinstance(recMsg, Msg) and recMsg.MsgType == 'text':
            toUser = recMsg.FromUserName
            fromUser = recMsg.ToUserName
            content = recMsg.Content.decode('utf-8')
            print('content = ', content)
            if self.is_asking_chatgpt(content):
                content = re.sub(pattern, '', content, flags=re.IGNORECASE)
                response_msg = '（本条消息为基于AI的自动回复）\n\n' + self.get_chatgpt_response(content)
                print('response_msg = ', response_msg)
                replyMsg = TextMsg(toUser, fromUser, response_msg)
                return replyMsg.send()
            else:
                print("暂且不处理 (不带有@AI)")
                return ''
        else:
            print("暂且不处理 (非文本消息)")
            return ''

    @staticmethod
    def is_asking_chatgpt(text):
        # text contains '@AI' (case insensitive)
        return re.search(pattern, text, flags=re.IGNORECASE)

    def get_chatgpt_response(self, in_msg):
        completion = self.client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": in_msg}]
        )
        out_msg = completion.choices[0].message.content
        return out_msg

    def parse_xml(self, web_data, encrypt_type, encodingAESKey, expected_app_id):
        if len(web_data) == 0:
            return None
        xmlData = ET.fromstring(web_data)

        if encrypt_type == 'aes':
            if xmlData.find('Encrypt') != None:
                xmlData = self.decrypt_msg(encodingAESKey, xmlData.find('Encrypt').text, expected_app_id)
                print('Decrypted XML: ', ET.tostring(xmlData, encoding='utf-8', method='xml'))

        msg_type_element = xmlData.find('MsgType')
        if msg_type_element is not None:
            msg_type = msg_type_element.text
            if msg_type == 'text':
                return TextMsg(xmlData=xmlData)
            elif msg_type == 'image':
                return ImageMsg(xmlData=xmlData)
        else:
            print("MsgType element not found in the XML.")

        return None

    def decrypt_msg(self, encodingAESKey, encrypted_data_b64, expected_app_id):
        encrypted_data = base64.b64decode(encrypted_data_b64)

        iv = encrypted_data[:16]
        data = encrypted_data[16:]
        aes_key_bytes = base64.b64decode(encodingAESKey + "=")
        cipher = Cipher(algorithms.AES(aes_key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt and remove PKCS#7 padding
        decrypted = decryptor.update(data) + decryptor.finalize()
        pad = decrypted[-1]
        decrypted = decrypted[:-pad]

        # Convert decrypted message to string and parse XML
        xml_len = socket.ntohl(struct.unpack("I",decrypted[ : 4])[0])
        xml_content = decrypted[4 : xml_len+4]
        from_appid = decrypted[xml_len+4:].decode('utf-8')
        if from_appid != expected_app_id:
            print("App ID mismatch! (expected: '{}', actual: '{}')".format(expected_app_id, from_appid))

        return ET.fromstring(xml_content)

    def encrypt_msg(self, plain_msg, token, timestamp, msg_signature, nonce, encodingAESKey, appId, toUserName, fromUserName):
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

        # Apply PKCS7 padding
        padder = padding.PKCS7(128).padder() # 128 bits = 16 bytes
        padded_data = padder.update(text_bytes) + padder.finalize()

        # Initialize the backend and cipher
        iv = os.urandom(16)  # AES block size is 16 bytes, ensure this matches your requirement
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded message
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
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
            'toUserName'    : toUserName,
            'fromUserName'  : fromUserName,
            'CreateTime'    : timestamp,
            'msg_encrypt'   : b64_encrypted,
            'msg_signaturet': msg_signature,
            'timestamp'     : timestamp,
            'nonce'         : nonce,
            }
        resp_xml = AES_TEXT_RESPONSE_TEMPLATE % resp_dict
        return resp_xml

class Msg(object):
    def __init__(self, xmlData=None):
        if xmlData is not None:
            self.ToUserName = self.get_element_text(xmlData, 'ToUserName')
            self.FromUserName = self.get_element_text(xmlData, 'FromUserName')
            self.CreateTime = self.get_element_text(xmlData, 'CreateTime')
            self.MsgType = self.get_element_text(xmlData, 'MsgType')
            self.MsgId = self.get_element_text(xmlData, 'MsgId')

    def send(self):
        return "success"

    @staticmethod
    def get_element_text(xmlData, tag):
        element = xmlData.find(tag)
        if element is not None:
            return element.text
        return None  # or return some default value or empty string

class TextMsg(Msg):
    def __init__(self, toUserName=None, fromUserName=None, content=None, xmlData=None):
        if xmlData is not None:
            super().__init__(xmlData)
            content = self.get_element_text(xmlData, 'Content')
            self.Content = content.encode("utf-8") if content is not None else None
        else:
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
    def __init__(self, toUserName=None, fromUserName=None, mediaId=None, xmlData=None):
        if xmlData is not None:
            super().__init__(xmlData)
            self.PicUrl = xmlData.find('PicUrl').text
            self.MediaId = xmlData.find('MediaId').text
        else:
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
