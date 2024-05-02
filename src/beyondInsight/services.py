"""Servcie Module, communication with external API's, components"""

import logging
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from . import settings, utils

req = requests.Session()

if not settings.BT_VERIFY_CA:
    utils.log("InsecureRequestWarning: Unverified HTTPS request is being made to host "
              f"{settings.BT_API_URL}'. Adding certificate verification is"
              "strongly advised. See: https://urllib3.readthedocs.io/en/1.26.x"
              "/advanced-usage.html#ssl-warnings",
              logging.WARN)

    req.verify = False

def sign_app_in():
    """
    Sign in to Secret safe API
    Arguments:
    Returns:
        logged user
    """
    url = f"{settings.BT_API_URL}/Auth/SignAppin"
    if settings.BT_CLIENT_CERTIFICATE_PATH:
        utils.log(f"Adding Certificate from: {settings.BT_CLIENT_CERTIFICATE_PATH}",
                  logging.INFO)
        with utils.pfx_to_pem(settings.BT_CLIENT_CERTIFICATE_PATH,
                              settings.BT_CLIENT_CERTIFICATE_PASSWORD) as cert:
            return send_post_sign_app_in(url, cert)

    else:
        utils.log("Certificate path was not configured", logging.INFO)
        return send_post_sign_app_in(url, None)

def sign_app_out():
    """
    Sign out to Secret safe API
    Arguments:
    Returns:
        Status of the action
    """

    url = f"{settings.BT_API_URL}/Auth/Signout"

    # Connection : close - tells the connection pool to close the connection.
    response = req.post(url, headers={'Connection':'close'})
    if response.status_code == 200:
        return True

    utils.log(f"sign_app_out: Error trying to sign app out: {response.text}")
    return False

def send_post_sign_app_in(url, cert):
    """
    Send Post request to Sign app in service
    Arguments:
    Returns:
        Service URL
        Certificate
    """
    try:
        response = req.post(url, headers=settings.REQUEST_HEADERS, cert=cert)
        if response.status_code == 200:
            utils.log("logged Succesfully", logging.INFO)
            return response.json(), None
        if response.status_code != 404:
            log_message = response.json()
            utils.log(f"sign_app_in: Error trying to sign app in: {log_message}, "
                f"Secret Safe API URL: {url}", logging.ERROR)
            return None, log_message
    except (requests.exceptions.SSLError) as error:
        log_message = f"SSL Error {error}"
        utils.log(log_message, logging.ERROR)
        return None, log_message
    except (requests.exceptions.ConnectionError) as error:
        log_message = f"Failed to establish a new connection to {settings.BT_API_URL}, {error}"
        utils.log(log_message, logging.ERROR)
        return None, log_message


def get_secret_by_path(path, title, separator, send_title=True):
    """
    Get secrets by path and title
    Arguments:
        Secret Path
        Secret Title
    Returns:
        Secret 
    """

    url = f"{settings.BT_API_URL}/secrets-safe/secrets?path={path}&separator={separator}"

    if send_title:
        url = f"{settings.BT_API_URL}/secrets-safe/secrets?title={title}&path={path}&separator={separator}"
    response = req.get(url, headers=settings.REQUEST_HEADERS)

    if response.status_code == 200:
        return response.json()

    utils.log(f"get_secret_by_path: Error trying to get secret by path: {path} and title {title}, response: {response.json()}", logging.ERROR)
    if not sign_app_out():
        utils.log("Eror trying to sign out!")
    return None

def get_secret_file_by_id(secret_id):
    """
    Get a File secret by File id
    Arguments:
        secret id
    Returns:
        File secret text
    """

    url = f"{settings.BT_API_URL}/secrets-safe/secrets/{secret_id}/file/download"
    response = req.get(url, headers=settings.REQUEST_HEADERS)
    if response.status_code == 200:
        return response.text

    utils.log(f"get_file_by_id: Error trying to get file by secret Id {secret_id}: {response.text}", logging.ERROR)
    if not sign_app_out():
        utils.log("Eror trying to sign out!")
    return None

def get_managed_accounts(system_name, account_name):
    """
    Get manage accounts by system name and account name
    Arguments:
        Secret id
    Returns:
        File secret text
    """

    url = f"{settings.BT_API_URL}/ManagedAccounts?systemName={system_name}&accountName={account_name}"
    response = req.get(url, headers=settings.REQUEST_HEADERS)

    if response.status_code == 200:
        return response.json()

    utils.log(f"get_managed_accounts: Error trying to get secret by system name: {system_name} and account name {account_name}, response: {response.json()}", logging.ERROR)
    if not sign_app_out():
        utils.log("Eror trying to sign out!")
    return None

def create_request_in_password_safe(system_id, account_id):
    """
    Create request by system id and account id
    Arguments:
        Secret id, Account id
    Returns:
        Request id
    """

    payload = {
        "SystemID": system_id,
        "AccountID": account_id,
        "DurationMinutes": 5,
        "Reason": "Test",
        "ConflictOption": "reuse"
    }

    url = f"{settings.BT_API_URL}/Requests"
    response = req.post(
        url, json=payload, headers=settings.REQUEST_HEADERS)
    
    if response.status_code in (200, 201):
        return response.json()

    utils.log(f"create_request: Error trying to create request, payload: {payload}, response: {response.json()}", logging.ERROR)
    if not sign_app_out():
        utils.log("Eror trying to sign out!")

    return None

def get_credential_by_request_id(request_id):
    """
    Get Credential by request id
    Arguments:
        Request id
    Returns:
        Credential info
    """

    url = f"{settings.BT_API_URL}/Credentials/{request_id}"
    response = req.get(url, headers=settings.REQUEST_HEADERS)
    if response.status_code == 200:
        return response.text.strip('"')
    
    utils.log(f"get_credential_by_request_id: Error trying to get credential by request id {request_id}, response: {response}", logging.ERROR)
    if not sign_app_out():
        utils.log("Eror trying to sign out!")
    return None


def request_check_in(request_id):
    """
    Expire request
    Arguments:
        Request id
    Returns:
        Informative text
    """

    url = f"{settings.BT_API_URL}/Requests/{request_id}/checkin"
    response = req.put(url, json={}, headers=settings.REQUEST_HEADERS)
    if response.status_code == 204:
        return True

    utils.log(f"request_check_in: Error trying to check in by reuqest id {request_id}, response: {response.text}", logging.ERROR)
    if not sign_app_out():
        utils.log("Eror trying to sign out!")
    return None