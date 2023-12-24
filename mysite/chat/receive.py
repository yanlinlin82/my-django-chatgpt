import base64
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct
import socket

def parse_xml(web_data, encrypt_type, encodingAESKey, expected_app_id):
    if len(web_data) == 0:
        return None
    xmlData = ET.fromstring(web_data)

    if encrypt_type == 'aes':
        if xmlData.find('Encrypt') != None:
            xmlData = decrypt_msg(encodingAESKey, xmlData.find('Encrypt').text, expected_app_id)

    msg_type_element = xmlData.find('MsgType')
    if msg_type_element is not None:
        msg_type = msg_type_element.text
        if msg_type == 'text':
            return TextMsg(xmlData)
        elif msg_type == 'image':
            return ImageMsg(xmlData)
    else:
        print("MsgType element not found in the XML.")

    return None

def decrypt_msg(encodingAESKey, encrypted_data_b64, expected_app_id):
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

class Msg(object):
    def __init__(self, xmlData):
        self.ToUserName = self.get_element_text(xmlData, 'ToUserName')
        self.FromUserName = self.get_element_text(xmlData, 'FromUserName')
        self.CreateTime = self.get_element_text(xmlData, 'CreateTime')
        self.MsgType = self.get_element_text(xmlData, 'MsgType')
        self.MsgId = self.get_element_text(xmlData, 'MsgId')

    @staticmethod
    def get_element_text(xmlData, tag):
        element = xmlData.find(tag)
        if element is not None:
            return element.text
        return None  # or return some default value or empty string

class TextMsg(Msg):
    def __init__(self, xmlData):
        super().__init__(xmlData)
        content = self.get_element_text(xmlData, 'Content')
        self.Content = content.encode("utf-8") if content is not None else None

class ImageMsg(Msg):
    def __init__(self, xmlData):
        super().__init__(xmlData)
        self.PicUrl = xmlData.find('PicUrl').text
        self.MediaId = xmlData.find('MediaId').text
