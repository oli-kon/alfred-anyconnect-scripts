from __future__ import print_function

import base64
import binascii
import hashlib
import hmac
import string
import sys
import time

# WORKAROUND BEGIN!!!!!!
sys.path.insert(0,"./lib")
import requests

from Crypto.Cipher import AES
from Crypto.Random import random
from lxml import etree
import oath
from oath import totp
# WORKAROUND END!!!!!!

PROVISIONING_URL = 'https://services.vip.symantec.com/prov'

HMAC_KEY = b'\xdd\x0b\xa6\x92\xc3\x8a\xa3\xa9\x93\xa3\xaa\x26\x96\x8c\xd9\xc2\xaa\x2a\xa2\xcb\x23\xb7\xc2\xd2\xaa\xaf\x8f\x8f\xc9\xa0\xa9\xa1'

TOKEN_ENCRYPTION_KEY = b'\x01\xad\x9b\xc6\x82\xa3\xaa\x93\xa9\xa3\x23\x9a\x86\xd6\xcc\xd9'

REQUEST_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8" ?>
<GetSharedSecret Id="%(timestamp)d" Version="2.0"
    xmlns="http://www.verisign.com/2006/08/vipservice"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <TokenModel>%(token_model)s</TokenModel>
    <ActivationCode></ActivationCode>
    <OtpAlgorithm type="%(otp_algorithm)s"/>
    <SharedSecretDeliveryMethod>%(shared_secret_delivery_method)s</SharedSecretDeliveryMethod>
    <DeviceId>
        <Manufacturer>%(manufacturer)s</Manufacturer>
        <SerialNo>%(serial)s</SerialNo>
        <Model>%(model)s</Model>
    </DeviceId>
    <Extension extVersion="auth" xsi:type="vip:ProvisionInfoType"
        xmlns:vip="http://www.verisign.com/2006/08/vipservice">
        <AppHandle>%(app_handle)s</AppHandle>
        <ClientIDType>%(client_id_type)s</ClientIDType>
        <ClientID>%(client_id)s</ClientID>
        <DistChannel>%(dist_channel)s</DistChannel>
        <ClientInfo>
            <os>%(os)s</os>
            <platform>%(platform)s</platform>
        </ClientInfo>
        <ClientTimestamp>%(timestamp)d</ClientTimestamp>
        <Data>%(data)s</Data>
    </Extension>
</GetSharedSecret>'''

class va_token:
    '''Class to generate VIP Access token and digits'''

    # members
    _token = None
    _key = None

    # methods
    def __init__(self):
        self._token = None
        self._key = None

    def __generate_request(self, **request_parameters):
        '''Generate a token provisioning request.'''

        default_model = 'MacBookPro%d,%d' % (random.randint(1, 12), random.randint(1, 4))
        default_request_parameters = {
            'timestamp':int(time.time()),
            'token_model':'VSST',
            'otp_algorithm':'HMAC-SHA1-TRUNC-6DIGITS',
            'shared_secret_delivery_method':'HTTPS',
            'manufacturer':'Apple Inc.',
            'serial':''.join(random.choice(string.digits + string.ascii_uppercase) for x in range(12)),
            'model':default_model,
            'app_handle':'iMac010200',
            'client_id_type':'BOARDID',
            'client_id':'Mac-' + ''.join(random.choice('0123456789ABCDEF') for x in range(16)),
            'dist_channel':'Symantec',
            'platform':'iMac',
            'os':default_model,
        }

        default_request_parameters.update(request_parameters)
        request_parameters = default_request_parameters

        data_before_hmac = u'%(timestamp)d%(timestamp)d%(client_id_type)s%(client_id)s%(dist_channel)s' % request_parameters
        request_parameters['data'] = base64.b64encode(
            hmac.new(
                HMAC_KEY,
                data_before_hmac.encode('utf-8'),
                hashlib.sha256
                ).digest()
            ).decode('utf-8')

        return REQUEST_TEMPLATE % request_parameters

    def __get_provisioning_response(self, request, session=requests):
        return session.post(PROVISIONING_URL, data=request)

    def __get_token_from_response(self, response_xml):
        ns = {'v':'http://www.verisign.com/2006/08/vipservice'}

        tree = etree.fromstring(response_xml)
        result = tree.find('v:Status/v:StatusMessage', ns).text

        if result == 'Success':
            token = {}
            token['timeskew'] = time.time() - int(tree.find('v:UTCTimestamp', ns).text)
            container = tree.find('v:SecretContainer', ns)
            encryption_method = container.find('v:EncryptionMethod', ns)
            token['salt'] = base64.b64decode(encryption_method.find('v:PBESalt', ns).text)
            token['iteration_count'] = int(encryption_method.find('v:PBEIterationCount', ns).text)
            token['iv'] = base64.b64decode(encryption_method.find('v:IV', ns).text)

            device = container.find('v:Device', ns)
            secret = device.find('v:Secret', ns)
            data = secret.find('v:Data', ns)
            expiry = secret.find('v:Expiry', ns)
            usage = secret.find('v:Usage', ns)

            token['id'] = secret.attrib['Id']
            token['cipher'] = base64.b64decode(data.find('v:Cipher', ns).text)
            token['digest'] = base64.b64decode(data.find('v:Digest', ns).text)
            token['expiry'] = expiry.text
            token['period'] = int(usage.find('v:TimeStep', ns).text)

            algorithm = usage.find('v:AI', ns).attrib['type'].split('-')
            if len(algorithm)==4 and algorithm[0]=='HMAC' and algorithm[2]=='TRUNC' and algorithm[3].endswith('DIGITS'):
                token['algorithm'] = algorithm[1].lower()
                token['digits'] = int(algorithm[3][:-6])
            else:
                raise RuntimeError('unknown algorithm %r' % '-'.join(algorithm))

            return token

    def configure_token(self):
        request = self.__generate_request(token_model='VSST')
        print("request is " + request)

        session = requests.Session()
        response = self.__get_provisioning_response(request, session)
        print("response is " + response.content)

        self._token = self.__get_token_from_response(response.content)
        print("token is " + self._token['id'])

        return True

    def __decrypt_key(self, token_iv, token_cipher):
        decryptor = AES.new(TOKEN_ENCRYPTION_KEY, AES.MODE_CBC, token_iv)
        decrypted = decryptor.decrypt(token_cipher)

        # "decrypted" has PKCS#7 padding on it, so we need to remove that
        if type(decrypted[-1]) != int:
            num_bytes = ord(decrypted[-1])
        else:
            num_bytes = decrypted[-1]
        otp_key = decrypted[:-num_bytes]

        return otp_key

    def get_digits(self):
        if self._token != None:
            secret = self.__decrypt_key(self._token['iv'], self._token['cipher'])
            secret_b32 = base64.b32encode(secret).upper().decode('ascii')
            print("secret is " + secret_b32)

            key = oath._utils.tohex( oath.google_authenticator.lenient_b32decode(secret_b32) )
            self._key = oath.totp(key)
            return True

        return False

    def isinitialized(self):
        if self._token is None:
            return False

        return True

    def get_secret_b32(self):
        if self._token is None:
            return None

        secret = self.__decrypt_key(self._token['iv'], self._token['cipher'])
        return base64.b32encode(secret).upper().decode('ascii')

    def get_id(self):
        if self._token is None:
            return None

        return self._token['id']

    def get_expiry(self):
        if self._token is None:
            return None

        return self._token['expiry']

    def get_key(self):
        return self._key

    def calculate_key(self, secret_b32):
        key = oath._utils.tohex( oath.google_authenticator.lenient_b32decode(secret_b32) )
        return oath.totp(key)


def test():
    res = 0

    print("VIPACCESS TEST")

    va = va_token()

    if va.configure_token() == True:
        va.get_digits()

    print("otp_key=" + va.get_key())

    return res

if __name__ == u'__main__':
    test()
