import os
env = os.environ



BT_API_URL = env['BT_API_URL']
REQUEST_HEADERS = {'Authorization': f"PS-Auth key={env['BT_API_KEY']}"}
BT_VERIFY_CA  = True if 'BT_VERIFY_CA' in env and env['BT_VERIFY_CA'].lower() == 'true' else False
FETCH_ALL_MANAGED_ACCOUNTS = False if 'FETCH_ALL_MANAGED_ACCOUNTS' in env and env['FETCH_ALL_MANAGED_ACCOUNTS'].lower() == 'false' else True

APP_PATH = "/usr/src/app"
DEFAULT_SECRETS_FOLDER = "secrets_files"
SECRETS_PATH = f"{APP_PATH}/{DEFAULT_SECRETS_FOLDER}"

if 'SECRETS_PATH' in env:
    SECRETS_PATH = env['SECRETS_PATH']
    if len(env['SECRETS_PATH'].strip()) == 0:
        SECRETS_PATH = f"{APP_PATH}/{DEFAULT_SECRETS_FOLDER}"

SECRETS_LIST = env['SECRETS_LIST'] if 'SECRETS_LIST' in env else ""
FOLDER_LIST = env['FOLDER_LIST'] if 'FOLDER_LIST' in env else ""
MANAGED_ACCOUNTS_LIST = env['MANAGED_ACCOUNTS_LIST'] if 'MANAGED_ACCOUNTS_LIST' in env else ""

BT_CLIENT_CERTIFICATE_PATH = None
if 'BT_CLIENT_CERTIFICATE_PATH' in env:
    if len(env['BT_CLIENT_CERTIFICATE_PATH']) > 0:
        BT_CLIENT_CERTIFICATE_PATH = env['BT_CLIENT_CERTIFICATE_PATH']

BT_CLIENT_CERTIFICATE_PASSWORD = env['BT_CLIENT_CERTIFICATE_PASSWORD'] if 'BT_CLIENT_CERTIFICATE_PASSWORD' in env and BT_CLIENT_CERTIFICATE_PATH else ""

EXCECUTION_ID = None

APP_VERSION = "2.0.0"