#!/usr/bin/env python3

import argparse
import json
import time
import os
import requests
import urllib3

# PowerProtect Data Manager lifecycle management automation
# Author - Idan Kentor <idan.kentor@dell.com>
# Version 1 - October 2023
# Version 2 - March 2024
# Version 3 - March 2025
# Copyright [2025] [Idan Kentor]

# Examples:
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -f /home/idan/dellemc-ppdm-upgrade-sw-19.19.0-15.pkg
# python ppdm_upgrade.py -s 10.0.0.1 -u idan -p "myTempPwd!"" -f c:\idan\dellemc-ppdm-upgrade-sw-19.19.0-15.pkg -onlyprecheck
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -skipupload -release 19.19.0-15
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -f c:\idan\dellemc-ppdm-upgrade-sw-19.19.0-15.pkg -skipsnapshot
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -onlymonitor


urllib3.disable_warnings()


def get_args():
    """Gets command line args from the user"""
    parser = argparse.ArgumentParser(
        description="Script to automate PowerProtect Data Manager lifecycle management"
    )
    parser.add_argument(
        "-s",
        "--server",
        required=True,
        dest="server",
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
    parser.add_argument(
        "-p",
        "--password",
        required=True,
        dest="password",
        action="store",
        help="PPDM password",
    )
    parser.add_argument(
        "-f",
        "--file",
        required=False,
        dest="upg_file",
        action="store",
        help="Full path to upgrade package",
    )
    parser.add_argument(
        "-onlyprecheck",
        "--only-pre-check",
        required=False,
        dest="pre_check",
        action="store_true",
        help="Optionally stops after pre-check",
    )
    parser.add_argument(
        "-skipupload",
        "--skip-file-upload",
        required=False,
        dest="skip_upload",
        action="store_true",
        help="Optionally skips file upload",
    )
    parser.add_argument(
        "-release",
        "--ppdm-release",
        required=False,
        dest="ppdm_release",
        action="store",
        help="Provide PPDM version if skipping package upload",
    )
    parser.add_argument(
        "-skipsnapshot",
        "--skip-snapshot",
        required=False,
        dest="skip_snapshot",
        action="store_true",
        help="Optionally skips PPDM VM snapshot",
    )
    parser.add_argument(
        "-onlymonitor",
        "--only-monitor",
        required=False,
        dest="just_monitor",
        action="store_true",
        help="Optionally only monitor running upgrade",
    )
    args = parser.parse_args()
    return args


def init_rest_call(verb, uri, token, payload=None, params=None):
    """Generic function for REST calls"""
    verify = False
    monitor = False
    timeout = 90
    code = {200, 201, 202, 204}
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    payload = json.dumps(payload)
    if uri.endswith("/login"):
        headers = {"Content-Type": "application/json"}
    elif uri.endswith("/upgrade/status"):
        headers.update({"Authorization": f"{token}"})
        monitor = True
    try:
        if verb.lower() == "get":
            response = requests.get(
                uri,
                headers=headers,
                params=params,
                verify=verify,
                timeout=timeout
            )
        else:
            response = requests.request(
                verb,
                uri,
                headers=headers,
                params=params,
                data=payload,
                verify=verify,
                timeout=timeout,
            )
        response.raise_for_status()
    except requests.exceptions.Timeout as error:
        print(f"-> Connection timed out:{uri} {error}")
        return False
    except requests.exceptions.ConnectionError as error:
        if not monitor:
            print(f"-> Error Connecting to {uri}: {error}")
        return False
    except requests.exceptions.RequestException as error:
        if response.status_code in (401, 502):
            return False
        print(f"-> The call {response.request.method} {response.url} failed with exception:{error}")
    if response.status_code not in code:
        raise requests.exceptions.HTTPError(
            f"-> Failed to query {uri}, code: {response.status_code}, body: {response.text}"
        )
    if not response.content:
        return True
    if uri.endswith("/login"):
        return response.json()["access_token"]
    try:
        return response.json()
    except AttributeError:
        return response.content


def check_deployment(ppdm_uri, token, post_deploy=None, target_ver=None):
    """Validates that PPDM is ready for upgrade and healthy post-upgrade"""
    ppdm_uri = f"{ppdm_uri}/nodes"
    nodes = init_rest_call("GET", ppdm_uri, token)
    ppdm_node = nodes["content"][0]
    if ppdm_node["status"] != "OPERATIONAL_RUNNING":
        if post_deploy:
            raise SystemExit(f"PPDM is on version {ppdm_node['version']} but with state {ppdm_node['status']}. Exiting...")
        raise SystemExit("PPDM is not upgrade ready. Exiting...")
    if post_deploy:
        if not target_ver:
            target_ver = ppdm_node["version"]
        if ppdm_node["version"] == target_ver:
            print(f"---> PPDM is operational on version {ppdm_node['version']}")
            return True
        raise SystemExit("Post-upgrade version checks failed. Exiting...")
    print("---> PPDM is upgrade ready")
    return ppdm_node["version"]


def perform_version_checks(ppdm_uri, token, current_ver, ppdm_release, upg_file):
    """Performs pre-upgrade version and upgrade package validations"""
    if ppdm_release:
        print("---> Checking upgrade to PPDM version:", ppdm_release)
        if current_ver == ppdm_release:
            raise SystemExit("Current PPDM version is identical to the intended version. Exiting...")
        query = f'packageVersion eq "{ppdm_release}" and category eq "ACTIVE"'
    else:
        file_name = os.path.basename(upg_file)
        pkg_ver = file_name.split("-sw-")[1].rsplit('.', 1)[0]
        print("---> Checking upgrade to PPDM version:", pkg_ver)
        if current_ver == pkg_ver:
            raise SystemExit("Current PPDM version is identical to the intended version. Exiting...")
        query = f'packageVersion eq "{pkg_ver}" and category eq "ACTIVE"'
    upg_uri = f"{ppdm_uri}/upgrade-packages"
    params = {"filter": query}
    response = init_rest_call("GET", upg_uri, token, None, params)
    try:
        return response["content"][0]
    except (IndexError, KeyError):
        query = 'category eq "ACTIVE"'
        params = {"filter": query}
        response = init_rest_call("GET", upg_uri, token, None, params)
        if len(response["content"]) > 0:
            print(
                "At least one upgrade package of a different version already exists - remove it and retry. Exiting..."
            )
            raise SystemExit(1) from FileExistsError
        return False


def check_hosting_vcenter(ppdm_uri, token):
    """Checks if there is a vCenter configured as hosting"""
    ppdm_uri = f"{ppdm_uri}/inventory-sources"
    query = 'type eq "VCENTER" and details.vCenter.hosting eq true and details.vCenter.internal eq false'
    params = {"filter": query}
    response = init_rest_call("GET", ppdm_uri, token, None, params)
    return bool(len(response["content"]) == 1)


def multipart_encoder(upg_file, boundary):
    """Yields multipart form data in chunks"""
    file_name = os.path.basename(upg_file)
    chunk_size = 8192
    yield f'--{boundary}\r\n'.encode()
    yield f'Content-Disposition: form-data; name="file"; filename="{file_name}"\r\n'.encode()
    yield b'Content-Type: application/octet-stream\r\n\r\n'
    with open(upg_file, 'rb') as file_handle:
        while chunk := file_handle.read(chunk_size):
            yield chunk
    yield f'\r\n--{boundary}--\r\n'.encode()


def upload_package(ppdm_uri, token, upg_file):
    """Uploads upgrade package to PPDM using custom multipart encoder"""
    try:
        boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}"
        }
        ppdm_uri = f"{ppdm_uri}/upgrade-packages"
        start_time = time.time()
        response = requests.post(
            ppdm_uri,
            headers=headers,
            data=multipart_encoder(upg_file, boundary),
            stream=True,
            timeout=90,
            verify=False
            )
        end_time = time.time()
    except IOError as error:
        print("Could not open upgrade package, exiting...")
        raise SystemExit(1) from error
    except MemoryError as error:
        print("Package upload failed due to insufficient memory/disk space. Exiting...")
        raise SystemExit(1) from error
    if response.status_code != 201:
        # if not response.json() or "id" not.json in response:
        print("Package upload failed, exiting...")
        raise SystemExit(1)
    time_diff = round(end_time - start_time)
    print(f"---> Upload completed successfully in {time_diff // 60} mins and {time_diff % 60} secs")
    return response.json()


def monitor_preupg_activity(ppdm_uri, token, upg_id, upg_timeout):
    """Monitors pre-upgrade tasks"""
    ppdm_uri = f"{ppdm_uri}/upgrade-packages/{upg_id}"
    interval = 5
    start = time.time()
    print(f"-> Monitoring upgrade ID {upg_id}")
    while True:
        if (time.time() - start) > upg_timeout:
            break
        response = init_rest_call("GET", ppdm_uri, token)
        try:
            if response["state"] in ("AVAILABLE", "INSTALLED"):
                print(f"---> Monitoring state {response['state']}")
                return True
            if response["state"] == "PROCESSING":
                print(f"---> Monitoring state {response['state']}")
            elif response["state"] in ("ERROR", "pre_check_FAILED"):
                print("\033[91m\033[1m->Pre-check failed:\033[39m")
                print(json.dumps(response, indent=4))
                return False
        except TypeError:
            pass
        time.sleep(interval)
    return False


def authenticate(ppdm_uri, username, password):
    """Login"""
    ppdm_uri = f"{ppdm_uri}/login"
    login_payload = {"username": username, "password": password}
    token = init_rest_call("POST", ppdm_uri, login_payload, login_payload)
    return token


def perform_pre_check(ppdm_uri, token, upg_id):
    """Executes pre-upgrade checks"""
    ppdm_uri = f"{ppdm_uri}/upgrade-packages/{upg_id}/precheck"
    response = init_rest_call("POST", ppdm_uri, token)
    return response


def upgrade_ppdm(ppdm_uri, token, upg_data):
    """Upgrades PPDM"""
    upg_uri = f"{ppdm_uri}/upgrade-packages/{upg_data['id']}"
    params = {"forceUpgrade": "true"}
    upg_data["sizeInBytes"] = int(float(upg_data["sizeInBytes"]))
    response = init_rest_call("PUT", upg_uri, token, upg_data, params)
    if "category" in response:
        if response["category"] == "ACTIVE":
            return True
    return False


def check_ppdm_availability(ppdm_uri, username, password):
    """Checks if PPDM is available after a successfull upgrade"""
    checks = 3
    interval = 30
    for _ in range(checks):
        response = authenticate(ppdm_uri, username, password)
        if not response:
            time.sleep(interval)
        else:
            return response
    return False


def monitor_upg_activity(
    ppdm_uri, upg_token, monitor_timeout, post_deploy=None
):
    """Continuously monitors PPDM upgrade operations"""
    ppdm_uri = f"{ppdm_uri}/upgrade/status"
    interval = 10
    component_timeout = 600
    component_interval = 30
    start = time.time()
    print("---> Monitoring PPDM upgrade")
    while True:
        if (time.time() - start) > monitor_timeout:
            break
        try:
            response = init_rest_call("GET", ppdm_uri, upg_token)
        except BaseException:
            time.sleep(component_interval)
            response = init_rest_call("GET", ppdm_uri, upg_token)
        componentstart = time.time()
        while not response:
            print("---> Polling timed out, retrying...")
            time.sleep(component_interval)
            response = init_rest_call("GET", ppdm_uri, upg_token)
            if (time.time() - componentstart) > component_timeout:
                print("Timed out waiting for upgrade to complete. Exiting...")
                raise SystemExit(1)
            if post_deploy:
                return "TIMEOUT"
        upg_state = response[0]
        if upg_state["upgradeStatus"] == "RUNNING":
            print(
                f"---> Upgrade status: {upg_state['upgradeStatus']} {upg_state['percentageCompleted']}%"
            )
            current_stage = upg_state["currentStage"]
            print(
                f"----> Upgrade info: current component: {current_stage['component']}, description: {current_stage['description']} {current_stage['percentageCompleted']}%"
            )
            print(
                f"----> Upgrade info: seconds elapsed / remaining: {upg_state['elapsedTime']} / {upg_state['estimatedRemainingTime']}"
            )
        elif upg_state["upgradeStatus"] == "PENDING":
            print(f"---> Upgrade status: {upg_state['upgradeStatus']}")
        elif upg_state["upgradeStatus"] == "COMPLETED":
            print(
                f"---> Upgrade status: {upg_state['upgradeStatus']} {upg_state['percentageCompleted']}%"
            )
            print(
                f"----> Upgrade completed in {upg_state['elapsedTime'] // 60} mins and {upg_state['elapsedTime'] % 60} seconds"
            )
            return True
        elif upg_state["upgradeStatus"] == "FAILED":
            print("---> PPDM Upgrade FAILED")
            current_stage = upg_state["currentStage"]
            print(
                f"----> Failed component: {current_stage['component']}, description {current_stage['description']}"
            )
            return False
        time.sleep(interval)
    return False


def main():
    # Args assignment
    args = get_args()
    server, upg_file = args.server, args.upg_file
    pre_check, skip_upload = args.pre_check, args.skip_upload
    username, password = args.username, args.password
    skip_snapshot, ppdm_release = args.skip_snapshot, args.ppdm_release
    just_monitor = args.just_monitor

    # Const definition
    api_endpoint = "/api/v2"
    api_port = 8443
    upg_port = 14443
    upg_timeout = 3600
    upg_token = "abcdefghijklmn"

    # Arguments check
    if skip_upload and not ppdm_release:
        print(
            "The PPDM release must be provided when skipping package upload. Exiting..."
        )
        raise SystemExit(1)
    if ppdm_release and not skip_upload:
        if upg_file:
            print(
                "---> Ignoring 'ppdm-release' parameter as it requires'skip-file-upload'"
            )
            ppdm_release = None
        else:
            print(
                "Upgrade package and 'skip-upload' parameters were not specified. Exiting..."
            )
            raise SystemExit(1)
    if not upg_file and not ppdm_release and not skip_upload and not just_monitor:
        print(
            "Need to specify either upgrade file or skip-upload or only-monitor. Exiting..."
        )
        raise SystemExit(1)

    # Logs into the PPDM API
    ppdm_uri = f"https://{server}:{api_port}{api_endpoint}"
    token = authenticate(ppdm_uri, username, password)

    # Monitors running upgrade if only-monitor is specified
    if just_monitor:
        if upg_file or skip_upload or ppdm_release:
            print("---> Ignoring parmaters because only-monitor is specified.")
        print(
            "-> only-monitor parameter provided. Monitoring currently running upgrade."
        )
        upg_uri = "https://{server}:{upg_port}"
        result = monitor_upg_activity(
            upg_uri, upg_token, upg_timeout, True
        )
        if result is True:
            print("\033[92m\033[1m-> PPDM upgraded successfully\033[0m")
        elif result is False:
            print("\033[91m\033[1m-> PPDM upgrade failed\033[39m")
            raise SystemExit(1)
        else:
            pass
        print("-> Making sure PPDM is up and running")
        token = check_ppdm_availability(ppdm_uri, username, password)
        if token:
            print("---> PPDM is available")
            check_deployment(ppdm_uri, token, True)
            raise SystemExit(0)
        raise SystemExit("---> PPDM is not available yet, check again later...")

    # Getting PPDM configuration
    print("-> Obtaining PPDM configuration information")
    current_ver = check_deployment(ppdm_uri, token)

    # Performs pre-upgrade version and upgrade package checks
    print("-> Performing pre-upgrade version checks")
    print("---> Current PPDM version:", current_ver)
    version_checks = perform_version_checks(
        ppdm_uri, token, current_ver, ppdm_release, upg_file
    )
    if skip_upload:
        upg_data = version_checks
    else:
        if not version_checks:
            print("-> Uploading PPDM upgrade package")
            upg_data = upload_package(ppdm_uri, token, upg_file)
            token = authenticate(ppdm_uri, username, password)
        else:
            print(
                "---> File upload skipped as a package of the same release already exists"
            )
            upg_data = version_checks
            print(upg_data, type(upg_data))
    upg_pkg_id = upg_data["id"]

    # Monitors upgrade package processing activity
    monitor_preupg_activity(ppdm_uri, token, upg_pkg_id, upg_timeout)

    # Executes and monitors pre-check
    print("-> Performing pre-upgrade checks")
    perform_pre_check(ppdm_uri, token, upg_pkg_id)
    monitor = monitor_preupg_activity(ppdm_uri, token, upg_pkg_id, upg_timeout)
    if not monitor:
        raise SystemExit(1)
    if pre_check:
        print("---> Pre-check parameter provided. Exiting")
        raise SystemExit(0)

    # Upgrading PPDM
    print("-> Upgrading PPDM to release", upg_data["packageVersion"])
    if skip_snapshot:
        upg_data["skipSnapshot"] = True
    if check_hosting_vcenter(ppdm_uri, token):
        print(
            "---> Skipping PPDM VM snapshot because hosting vCenter is not configured"
        )
        upg_data["skipSnapshot"] = True
    upg_data["state"] = "INSTALLED"
    upg_data["lockboxPassphrase"] = "1234567890abcdef"
    upg_data["upgradeToken"] = upg_token
    upg_data["certificateTrustedByUser"] = True
    upg_data["eula"] = {"productEulaAccepted": True}
    if upgrade_ppdm(ppdm_uri, token, upg_data):
        upg_uri = f"https://{server}:{upg_port}"
        result = monitor_upg_activity(
            upg_uri, upg_data["upgradeToken"], upg_timeout
        )
        if result:
            print("\033[92m\033[1m-> PPDM upgraded successfully\033[0m")
        else:
            print("\033[91m\033[1m-> PPDM upgrade failed\033[39m")
            raise SystemExit(1)
    else:
        print("\033[91m\033[1m-> PPDM upgrade failed\033[39m")
        raise SystemExit(1)

    # PPDM post-upgrade checks
    print("-> Making sure PPDM is up and running")
    token = check_ppdm_availability(ppdm_uri, username, password)
    if token:
        print("---> PPDM is available")
        check_deployment(ppdm_uri, token, True, upg_data["packageVersion"])
        print("-> All tasks completed successfully")
    else:
        print("---> PPDM is not available yet, check again later...")


if __name__ == "__main__":
    main()
