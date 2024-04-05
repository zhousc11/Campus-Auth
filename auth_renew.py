import hashlib
import json
import logging
import os
import re
import sys
import time
from typing import Dict

from dotenv import load_dotenv

from auth import login
from utils.base64 import get_base64
from utils.utils import analysis_jsonp, hmac_md5, get_chkstr

import requests

from utils.xencode import get_xencode

# set logging format
logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', level=logging.INFO)


class CampusNetwork:
    # initialize the class variable
    _params = None

    # load json configures as a public profile so that all the instances share the same configure
    @classmethod
    def load_params(cls, config_file='parameters.json') -> Dict:
        if cls._params is None:
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    cls._params = json.load(f)
            except FileNotFoundError as e:
                logging.error(f'{e}: Parameter file not found. '
                              f'Check your current dir to see if there is a file named "parameters.json".')
                cls._params = {}
            except json.JSONDecodeError as e:
                logging.error(f'{e}: Parameter decode error due to invalid parameter file. '
                              f'Check your parameter file to see if it is a valid JSON file.')
                cls._params = {}
            except PermissionError as e:
                logging.error(f'{e}: Permission denied. '
                              f'Check your permission to read the file "parameters.json".')
                cls._params = {}
            except Exception as e:
                logging.error(f'{e}: Unknown error occurred. '
                              f'Please check the error message above to see what happened.')
                cls._params = {}
        return cls._params

    @property
    def params(self):
        return self.load_params()

    def __init__(self):
        self.callback = "jQuery112405642667473880212_" + str(int(time.time()))

    @staticmethod
    def get_token(headers, url_get_challenge, callback, username, ip) -> str:
        try:
            get_challenge_params = {
                'callback': callback,
                'username': username,
                'ip': ip,
                '_': str(int(time.time()))
            }
            response = requests.get(url_get_challenge, headers=headers,
                                    params=get_challenge_params)
            response.raise_for_status()
            return analysis_jsonp(response)['challenge']
        except requests.HTTPError as e:
            logging.error(f'Failed to get token: {e}')
            sys.exit()
        except requests.RequestException as e:
            logging.error(f'Failed to get token: {e}')
            sys.exit()
        except KeyError as e:
            logging.error(f'Response parsing error, missing key: {e}')

    @staticmethod
    def switch_id(ip_address: str) -> (str, str):
        load_dotenv()
        first_two_digits = ip_address.split('.')[:2]
        lan = first_two_digits == ['10', '31']

        username = os.environ.get('USERNAME_STUDENT_ID') if lan else os.environ.get('USERNAME_PHONE')
        password = os.environ.get('PASSWORD_STUDENT_ID') if lan else os.environ.get('PASSWORD_PHONE')

        if (username or password) is None:
            logging.error('Environment variables USERNAME_STUDENT_ID and PASSWORD_STUDENT_ID are not set')
            sys.exit()
        logging.info(f'Current logging Username: {username}')

        return username, password

    # get local ip address for different networks
    def get_local_ip(self, headers) -> str:
        try:
            homepage_url = self.params.get("homepage_url")
            init_res = requests.get(homepage_url, headers=headers)
            init_res.raise_for_status()
            pattern = r'ip\s+:\s+"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)"'
            match = re.search(pattern, init_res.text)
            ip_address = match.group(1)

            logging.info(f'Get current local ip address successfully: {ip_address}')

            return ip_address
        except requests.RequestException as e:
            logging.error(f'Failed to get current local ip address: {e}')
            sys.exit()

    def encrypt_sign(self, headers, url_get_challenge, username, password, ip, callback, ac_id, enc):
        token = self.get_token(headers, url_get_challenge, callback, username, ip)
        hmd5 = hmac_md5(password, token)
        logging.info("hmd5 : " + hmd5)
        info = {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": ac_id,
            "enc_ver": enc
        }
        i = "{SRBX1}" + get_base64(get_xencode(json.dumps(info), token))
        logging.info("i : " + i)
        logging.info("Data encryption completed successfully.")
        return i, hmd5, token

    @staticmethod
    def login(headers, url_srun_portal, username, ip, ac_id, i, hmd5, chksum, n, category, operate_system, name,
              callback):
        try:
            srun_portal_params = {
                'callback': callback,
                'action': 'login',
                'username': username,
                'password': '{MD5}' + hmd5,
                'ac_id': ac_id,
                'ip': ip,
                'chksum': chksum,
                'info': i,
                'n': n,
                'type': category,
                'os': operate_system,
                'name': name,
                'double_stack': '1',
                '_': str(int(time.time()))
            }

            srun_portal_response = requests.get(url_srun_portal, headers=headers, params=srun_portal_params)
            srun_portal_response.raise_for_status()
            srun_portal_response_json = analysis_jsonp(srun_portal_response)

            if srun_portal_response_json["error"] == "ok":
                logging.info(f'Login successfully: {username} logged in at {ip}')
            else:
                logging.error(f'Login failed: {srun_portal_response_json.get("error_msg")}')
        except requests.RequestException as e:
            logging.error(e)
            sys.exit()

    def start(self):
        params = self.params
        username, password = self.switch_id(self.get_local_ip(params.get('headers')))
        ip = self.get_local_ip(params.get('headers'))
        i, hmd5, token = self.encrypt_sign(params['headers'], params['url_get_challenge'],
                                           username, password, ip,
                                           self.callback, params['ac_id'], params['enc'])
        checkstr = get_chkstr(token, username, hmd5, params['ac_id'],
                              ip, params['n'], params['category'], i)
        checksum = hashlib.sha1(checkstr.encode()).hexdigest()
        login(params['headers'], params['url_srun_portal'], username, ip,
              params['ac_id'], i, hmd5, checksum, params['n'], params['category'],
              params['operate_system'], params['name'], self.callback)
        logging.info('Task completed successfully')


if __name__ == '__main__':
    CampusNetwork().start()
