import hashlib
import hmac
import json
import logging
import sys
import re
import requests


# analysis jsonp data
def analysis_jsonp(response):
    try:
        jsonp_response = response.text
        json_data = re.search(r'\(({.*)\)', jsonp_response).group(1)
        data = json.loads(json_data)
        logging.info(f'Successfully parse jsonp data: {json_data}')
        return data
    except json.JSONDecodeError as e:
        logging.error(f'Failed to parse jsonp data: {e}')
        sys.exit()


# concatenate the strings
def get_chkstr(token, username, hmd5, ac_id, ip, n, category, i):
    parts = [username, hmd5, ac_id, ip, n, category, i]
    chkstr = token + token.join(parts)
    return chkstr


def hmac_md5(message, key) -> str:
    hmac_hash = hmac.new(key.encode(), message.encode(), hashlib.md5)
    return hmac_hash.hexdigest()
