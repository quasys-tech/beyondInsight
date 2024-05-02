"""Controller Module, all the logic to process retrieved secrets"""

import logging
import traceback
import json

from . import services, settings, utils

def get_secrets():
    """
    Get All secrets in folder or get by secret id
    Argulemts:
    Returns
    """
    utils.log(f"APP VERSION: {settings.APP_VERSION}", logging.INFO)

    utils.log(f"Starting Execution...{settings.EXCECUTION_ID}", logging.INFO)
    utils.log(f"Getting secrets..", logging.INFO)

    # Get parameters from environment variables / (settings).
    secret_list = settings.SECRETS_LIST.lower()
    folder_list=settings.FOLDER_LIST.lower()
    managed_account_list=settings.MANAGED_ACCOUNTS_LIST.lower()

    execution_log = {
        'execution_id': str(settings.EXCECUTION_ID),
        'input': {
            'secret_list': secret_list,
            'managed_account_list': managed_account_list,
            'secret_safe_url': settings.BT_API_URL,
            'user': None,
        },
        'output': {
            'secrets': [],
            'messages': [],
            'errors': []
        }
    }

    try:
        # Call Sign App in service
        user, error = sign_app_in()

        if not error:
            execution_log['input']['user'] = user

            logs, secrets = get_secrets_from_bt(secret_list, folder_list, managed_account_list)

            execution_log['output']['errors'] = [log for log in logs if log['type'] == 'ERROR']
            execution_log['output']['messages'] = [log for log in logs if log['type'] == 'INFO']

            # Call Sign App Out service
            if not sign_app_out():
                utils.log("Eror trying to sign out!", logging.ERROR)

            execution_log_dump = json.dumps(execution_log, indent=4)

            utils.log(execution_log_dump, logging.INFO)
            utils.log(f"Ending Execution... {settings.EXCECUTION_ID}", logging.INFO)
            return secrets
        return None
    except Exception as error:
        traceback.print_exc()
        utils.log(f"There was an error in the execution: {error}", logging.ERROR)


def sign_app_in():
    """
    Call Sign app in service
    Arguments:
    Returns
    """

    return services.sign_app_in()

def sign_app_out():
    """
    Call Sign app out service
    Arguments:
    Returns
    """

    return services.sign_app_out()

def get_secrets_from_bt(secrets_list, folder_list, managed_accounts_list):
    """
    Get secrets by secret list / folder list and managed accounts list
    Arguments:
        Secret list
        Folder list
        Managed accounts list
    Returns
        Logs
        Retrieved secrets
    """

    secrets_to_file = []
    secrets_logs = []

    if secrets_list or folder_list:
        # Getting (credentials, text and files secrets)
        logs, secrets = get_secrets_by_folder_path_or_secret_path(secrets_list, folder_list)

        secrets_to_file.extend(secrets)
        if logs:
            secrets_logs.extend(logs)

    # Managed Account
    if managed_accounts_list:
        # Getting credentials by system name and account name.
        logs, secrets = get_secret_by_system_name_and_account_name(managed_accounts_list)
        secrets_to_file.extend(secrets)
        if logs:
            secrets_logs.extend(logs)
    elif settings.FETCH_ALL_MANAGED_ACCOUNTS:
        managed_accounts_list = get_managed_accounts()
        # Getting credentials by system name and account name.
        logs, secrets = get_secret_by_system_name_and_account_name(managed_accounts_list)
        secrets_to_file.extend(secrets)
        if logs:
            secrets_logs.extend(logs)
    secrets = generate_secret_json_array(secrets_to_file)
    # log_message = f"Creating files with the secrets as content, number of files {len(secrets_to_file)}"
    # secrets_logs.append({'message': log_message, 'type': 'INFO'})
    # utils.log(f"Secrets folder Path {settings.SECRETS_PATH}", logging.INFO)
    # utils.log(log_message, logging.INFO)

    # # Creating files in volume
    # utils.credential_to_file(secrets_to_file)

    return (secrets_logs, secrets)


def get_secrets_by_folder_path_or_secret_path(secrets_by_secret_path, secrets_by_folder_path):
    """
    Get secrets by folder path or secret path
    Arguments:
        Folder path or Folder secret
    Returns
        Logs
        Retrieved secrets from specific path
    """

    separator = '/'

    secrets = []
    secrets_logs = []

    if secrets_by_secret_path:
        paths = secrets_by_secret_path.split(",")
        for secret_path in paths:
            if secret_path == "":
                continue
            folders_in_path = secret_path.strip().split(separator)
            title = folders_in_path[-1]
            path = separator.join(folders_in_path[:-1])
            # Checking if it is a single password.
            response = services.get_secret_by_path(path, title, separator)
            
            if not response:
                utils.log(f"Secret {path}/{title} was not Found, Validating Folder: {folders_in_path}", logging.INFO)
                response = services.get_secret_by_path(separator.join(folders_in_path), title, separator, False)

                if not response:
                    log_message = f"Invalid path or Invalid Secret: {secret_path}"
                    secrets_logs.append({
                        'message': log_message,
                        'type': "ERROR"
                        })
                    utils.log(log_message, logging.ERROR)
                    continue

                for secret in response:
                    
                    secret_object = get_secrets_in_folder(secret)
                    if secret_object:
                        secrets.append(secret_object)

            elif response[0]['SecretType'] == "File":
                file = services.get_secret_file_by_id(response[0]['Id'])
                if not file:
                    log_message = f"Error Getting File secret, secret metadata: {response[0]}"
                    utils.log(log_message, logging.ERROR)
                    continue
                secrets.append(utils.create_secret_file(response[0], file))

            else:
                secrets.append(utils.convert_secret_to_object(response[0]))

    if secrets_by_folder_path:
        # Getting secrets by folder
        
        folders =  secrets_by_folder_path.split(",")
        utils.log(f"Getting secrets by folders {folders}", logging.INFO)

    
        for folder in folders:
            
            response = services.get_secret_by_path(folder, "", separator, False)

            if not response:
                log_message = f"Invalid path or Invalid Secret: {folder}"
                secrets_logs.append({
                    'message': log_message,
                    'type': "ERROR"
                    })
                utils.log(log_message, logging.ERROR)
                continue

            for secret in response:
                secret_object = get_secrets_in_folder(secret)
                if secret_object:
                    secrets.append(secret_object)

    return secrets_logs, secrets


def get_secrets_in_folder(secret):
    """
    Get specific secret object as json
    Arguments:
        secret response
    Returns
        secret object
    """

    if secret['SecretType'] == "File":
        file = services.get_secret_file_by_id(secret['Id'])
        if not file:
            log_message = f"Error Getting File secret, secret metadata: {secret}"
            utils.log(log_message, logging.ERROR)
            return False
        return utils.create_secret_file(secret, file)
    else:
        return utils.convert_secret_to_object(secret)


def get_secret_by_system_name_and_account_name(system_name_account_name):
    """
    Get secrets by system name and account name
    Arguments:
        System name
        Account Name
    Returns
        Logs
        Retrieved secrets
    """

    if not system_name_account_name:
        return [], []

    secrets = []
    secrets_logs = []

    system_name_account_name_items = system_name_account_name.split(",")

    for system_name_account_name_item in system_name_account_name_items:

        data = system_name_account_name_item.strip().split("/")

        if len(data) != 2:
            log_message = f"Invalid Managed Account: {system_name_account_name_item.strip()}"
            secrets_logs.append({
                'message': log_message,
                'type': "ERROR"
                })
            utils.log(log_message, logging.ERROR)
            continue

        system_name = data[0]
        account_name = data[1]

        secret_path = f"{system_name}/{account_name}"

        manage_account = services.get_managed_accounts(
            system_name, account_name)
        if manage_account is None or manage_account == 'Managed Account not found':
            log_message = f"Invalid Managed Account: {secret_path}"
            secrets_logs.append({
                'message': log_message,
                'type': "ERROR"
                })
            utils.log(log_message, logging.ERROR)
            continue

        request_id = services.create_request_in_password_safe(
            manage_account['SystemId'], manage_account['AccountId'])

        credential = services.get_credential_by_request_id(request_id)
        secrets.append(utils.convert_managed_account_to_object(manage_account, credential))
        services.request_check_in(request_id)

    return secrets_logs, secrets

def generate_secret_json_array(secrets):
    """
    Generate Secrets Json
    Arguments:
        Secrets
    Returns
        Secrets Json
    """
    parent_child_dict = {}
    for item in secrets:
        folder_path = item["FolderPath"]
        folders = folder_path.split('/')
        current_dict = parent_child_dict

        for folder in folders:
            if folder not in current_dict:
                if "AccountName" in item and folder == folders[-1]:
                    current_dict[folder] = item
                else:
                    current_dict[folder] = {}
            current_dict = current_dict[folder]
            
        
        if "Title" in item:
            current_dict[item["Title"]] = item
    
    result_json = json.dumps(parent_child_dict, indent=4)
    return result_json

def get_managed_accounts():
    separator = ','
    manage_account_list = []
    managed_accounts = services.get_managed_accounts("", "")
    for managed_account in managed_accounts:
        manage_account_list.append(f"{managed_account['SystemName']}/{managed_account['AccountName']}")
    return separator.join(manage_account_list)