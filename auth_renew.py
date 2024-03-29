import hashlib
import hmac
import json
import logging
import os
import re
import time
from typing import Dict

import requests
from dotenv import load_dotenv

from encrypt.base64 import get_base64
from encrypt.xencode import get_xencode

# set logging format
logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', level=logging.INFO)

class CampusNetwork:
    def __init__(self):
