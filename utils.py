"""Utils Module, common methods used in all project"""

import os
import json
import sys

import logging

from beyondtrust_agent import settings

import contextlib
import OpenSSL.crypto
import os
import tempfile

import uuid


if not settings.EXCECUTION_ID:
    settings.EXCECUTION_ID = uuid.uuid1()

log_format = " {asctime} {levelname} (" + str(settings.EXCECUTION_ID) + ") {message}"

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format=log_format,
    style='{'
    )

def log(message, level=logging.DEBUG):
    """
    Write log
    Arguments:
        Log message
        Log level
    Returns:
    """

    if level == logging.DEBUG:
        logging.debug(message)
    elif level == logging.INFO:
        logging.info(message)
    elif level == logging.ERROR:
        logging.error(message)
    elif level == logging.WARN:
        logging.warning(message)

def convert_secret_to_object(secret):
    """
    Convert secret response to json object
    Arguments:
        Secret Response
    Returns:
        Secret Json Object
    """
    data = {
        "Password": secret["Password"],
        "Title": secret["Title"],
        "Username": secret["Username"],
        "FolderPath": secret["FolderPath"],
        "FilePath": "",
        "IsFileSecret": False
    }
    return data

def convert_managed_account_to_object(secret, content):
    """
    Convert secret response to json object
    Arguments:
        Secret Response
    Returns:
        Secret Json Object
    """
    data = {
        "Password": content,
        "SystemName": secret["SystemName"],
        "AccountName": secret["AccountName"],
        "FolderPath": f"{secret['SystemName']}/{secret['AccountName']}",
        "IsFileSecret": False
    }
    return data

def create_secret_file(secret, content):
    """
    Create secret file
    Arguments:
        Secret Response
        Secret Content
    Returns:
        Secret Json Object
    """

    # This object keeps files paths and files content to be stored later on. 
    path = secret['FolderPath'].replace('\\', "/")
    path = f"{path}/{secret['Title']}"
    
    file_path = create_folders(path)
    if os.path.exists(file_path):
        os.remove(file_path)

    f = open(file_path, "a")
    f.write(content)
    f.write("\n")
    f.close()

    data = {
        "Password": secret["Password"],
        "Title": secret["Title"],
        "Username": secret["Username"],
        "FolderPath": secret["FolderPath"],
        "FilePath": file_path,
        "IsFileSecret": True
    }
    return data
        

        


def create_folders(path):
    """
    Create secret files folders in memory
    Arguments:
        Folder Path
    Returns:
        Created Folder Path
    """

    folders = path.split("/")
    secret_name = folders[-1]
    parent_folders = folders[0:-1]
    concat_folder = settings.SECRETS_PATH
    for folder in parent_folders:
        concat_folder = f"{concat_folder}/{folder}"
        if not os.path.exists(concat_folder):
            os.makedirs(concat_folder)
    return f"{concat_folder}/{secret_name}"


@contextlib.contextmanager
def pfx_to_pem(pfx_path, pfx_password):
    """
    Decrypts the .pfx file to be used with requests
    Arguments:
        PFX path
        PFX Password
    Returns:
        PEM file name
    """

    with tempfile.NamedTemporaryFile(suffix='.pem') as t_pem:
        f_pem = open(t_pem.name, 'wb')
        pfx = open(pfx_path, 'rb').read()
        p12 = OpenSSL.crypto.load_pkcs12(pfx, pfx_password)
        f_pem.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()))
        f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12.get_certificate()))
        ca = p12.get_ca_certificates()
        if ca is not None:
            for cert in ca:
                f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        f_pem.close()
        CERT = t_pem.name
        yield t_pem.name