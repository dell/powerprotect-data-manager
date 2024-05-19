#!/usr/bin/env python3

import argparse
import os.path
import json
import requests
import urllib3
from cryptography.fernet import Fernet

# This script purpose is to assist with PowerProtect Data Manager secure login
# Author - Idan Kentor <idan.kentor@dell.com>
# Version 1 - May 2024
# Copyright [2024] [Idan Kentor]

# Examples:
# python secure_login_helper.py --secure-file-path c:\my_vault --ppdm 10.0.0.1
# python secure_login_helper.py --password MyTestPwd! --secure-file-path c:\my_vault --ppdm 10.0.0.1
# python secure_login_helper.py --password MyTestPwd! --no-secure-password-file
# python secure_login_helper.py --clear-password-file --secure-file-path c:\repo


urllib3.disable_warnings()


def get_args():
    """Gets command line args from the user"""
    parser = argparse.ArgumentParser(
        description="Facilitate PPDM credentials management for REST API auth"
    )
    parser.add_argument(
        "-securefilepath",
        "--secure-file-path",
        required=False,
        dest="file_path",
        action="store",
        help="Provide the directory of the secure files",
    )
    parser.add_argument(
        "-pass",
        "--password",
        required=False,
        dest="password",
        action="store",
        help="Specify clear text password",
    )
    parser.add_argument(
        "-clear-file",
        "--clear-password-file",
        required=False,
        dest="clear_password_file",
        action="store",
        help="full path to clear text password file",
    )
    parser.add_argument(
        "-nosecurepassfile",
        "--no-secure-password-file",
        required=False,
        dest="no_secure_file",
        action="store_true",
        help="Optionally bypass secure password file creation",
    )
    parser.add_argument(
        "-ppdm",
        "--ppdm",
        required=False,
        dest="ppdm",
        action="store",
        help="PPDM server FQDN or IP",
    )
    parser.add_argument(
        "-u",
        "--username",
        required=False,
        dest="username",
        action="store",
        default="admin",
        help="Optionally provide the PPDM username",
    )
    args = parser.parse_args()
    return args


def encrypt_pwd(password):
    """Encrypts password using Fernet from clear text"""
    key = Fernet.generate_key()
    fernet_key = Fernet(key)
    password_bytes = bytes(password, "utf-8")
    encrypted_password_bytes = fernet_key.encrypt(password_bytes)
    encrypted_password = encrypted_password_bytes.decode("utf-8")
    key = key.decode("utf-8")
    return encrypted_password, key


def decrypt_pwd(encrypted_password, key):
    """Decrypts password using encrypted password and key"""
    encrypted_password_bytes = bytes(encrypted_password, "utf-8")
    key_bytes = bytes(key, "utf-8")
    fernet_key = Fernet(key_bytes)
    password_bytes = fernet_key.decrypt(encrypted_password_bytes)
    password = password_bytes.decode("utf-8")
    return password


def authenticate(ppdm, uri, user, password):
    """Logins to PowerProtect Data Manager"""
    suffixurl = "/login"
    verify = False
    timeout = 90
    uri += suffixurl
    headers = {'Content-Type': 'application/json'}
    payload = {"username": user, "password": password}
    payload = json.dumps(payload)
    try:
        response = requests.post(
            uri,
            data=payload,
            headers=headers,
            verify=verify,
            timeout=timeout
        )
        response.raise_for_status()
    except requests.exceptions.ConnectionError as err:
        print(f"Error Connecting to {ppdm}: {err}")
        raise SystemExit(1) from err
    except requests.exceptions.Timeout as err:
        print(f"Connection timed out {ppdm}: {err}")
        raise SystemExit(1) from err
    except requests.exceptions.RequestException as err:
        print(f"The call {response.request.method} {response.url} failed with exception:{err}")
        raise SystemExit(1) from err
    if response.status_code != 200:
        raise SystemExit(f"Login failed for user: {user}, code: {response.status_code}, body: {response.text}")
    print(f"Login for user: {user} to PPDM: {ppdm}")
    token = response.json()["access_token"]
    return token


def read_file(secure_file_path, file):
    """Reads secure files"""
    file_path = os.path.join(secure_file_path, file)
    with open(file_path, "r", encoding="utf-8") as file_handle:
        item = ''.join(file_handle.readlines())
    file_handle.close()
    return item


def write_file(secure_file_path, file, data):
    """Writes encrypted password and key to files in the secure path"""
    file_path = os.path.join(secure_file_path, file)
    with open(file_path, "wb") as file_handle:
        data_bytes = bytes(data, "utf-8")
        file_handle.write(data_bytes)
    file_handle.close()


def main():
    args = get_args()
    password, clear_password_file = args.password, args.clear_password_file
    no_secure_file, secure_file_path = args.no_secure_file, args.file_path
    username, ppdm = args.username, args.ppdm
    password_file_name = "pwd"
    key_file_name = "key"
    api_port = 8443
    api_endpoint = "/api/v2"
    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    if secure_file_path:
        if password or clear_password_file:
            print("-> Both password and file provided. Using secure password file")
        encrypted_password = read_file(secure_file_path, password_file_name)
        key = read_file(secure_file_path, key_file_name)
        password = decrypt_pwd(encrypted_password, key)
    else:
        if password and clear_password_file:
            print("-> Both password and file provided. Using provided password")
        if not password and clear_password_file:
            password = read_file(args.secure_file_path, password_file_name)
        if not password and not clear_password_file:
            raise SystemExit("-> No password specified. Exiting")
        if not no_secure_file:
            encrypted_password, key = encrypt_pwd(password)
            print("Writing password and key files to directory:", secure_file_path)
            write_file(secure_file_path, password_file_name, encrypted_password)
            write_file(secure_file_path, key_file_name, key)
    if args.ppdm:
        token = authenticate(ppdm, uri, username, password)
        print("PPDM access token:")
        print(token)
    else:
        print("No PowerProtect Data Manager host specified. Exiting")


if __name__ == "__main__":
    main()
