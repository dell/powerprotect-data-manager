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
# Version 4 - July 2025
# Version 5 - November 2025

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
        description="Automate PowerProtect Data Manager lifecycle management"
    )
    parser.add_argument(
        "-s", "--server",
        required=True,
        help="PPDM server FQDN or IP",
    )
    parser.add_argument(
        "-u", "--username",
        default="admin",
        help="PPDM username (default: admin)",
    )
    parser.add_argument(
        "-p", "--password",
        required=True,
        help="PPDM password",
    )
    parser.add_argument(
        "-f", "--file",
        dest="upg_file",
        help="Full path to the upgrade package",
    )
    parser.add_argument(
        "-release", "--ppdm-release",
        dest="ppdm_release",
        help="Provide PPDM version if skipping package upload",
    )
    parser.add_argument(
        "-onlyprecheck", "--only-pre-check",
        dest="pre_check",
        action="store_true",
        help="Perform only the pre-check",
    )
    parser.add_argument(
        "-skipupload", "--skip-file-upload",
        dest="skip_upload",
        action="store_true",
        help="Skip upgrade package upload",
    )
    parser.add_argument(
        "-skipsnapshot", "--skip-snapshot",
        dest="skip_snapshot",
        action="store_true",
        help="Skip PPDM VM snapshot",
    )
    parser.add_argument(
        "-onlymonitor", "--only-monitor",
        dest="just_monitor",
        action="store_true",
        help="Only monitor a running upgrade",
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
        print(f"-> Connection timed out: {uri} {error}")
        return False
    except requests.exceptions.ConnectionError as error:
        if not monitor:
            print(f"-> Error Connecting to {uri}: {error}")
        return False
    except requests.exceptions.RequestException as error:
        if not response:
            return False
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


def check_deployment_type(ppdm_uri, token, bm_check):
    """Validates that PPDM deployment type"""
    config_uri = f"{ppdm_uri}/configurations"
    config = init_rest_call("GET", config_uri, token)

    if not config or "content" not in config:
        raise SystemExit("---> PPDM is not available. Exiting...")

    deploy_type = config["content"][0].get("deployedPlatform", "UNKNOWN")

    if deploy_type == bm_check:
        deploy_type = "baremetal"
        print(f"---> PPDM is deployed as {deploy_type}")
        raise SystemExit(f"---> Solution is not supported on {deploy_type}. Exiting...")

    print(f"---> PPDM is deployed on {deploy_type}")
    return True


def check_deployment(ppdm_uri, token, post_deploy=None, target_ver=None):
    """Validates that PPDM is ready for upgrade and healthy post-upgrade"""
    nodes_uri = f"{ppdm_uri}/nodes"
    retry_interval = 60
    nodes = init_rest_call("GET", nodes_uri, token)

    if not nodes or not isinstance(nodes, dict) or "content" not in nodes:
        time.sleep(retry_interval)
        nodes = init_rest_call("GET", nodes_uri, token)
        if not nodes or not isinstance(nodes, dict) or "content" not in nodes:
            raise SystemExit("Cannot query the Data Manager server. Exiting...")

    ppdm_node = nodes["content"][0]
    status = ppdm_node.get("status")
    version = ppdm_node.get("version")

    if status != "OPERATIONAL_RUNNING":
        if post_deploy:
            raise SystemExit(f"PPDM is on version {version} but with state {status}. Exiting...")
        raise SystemExit("PPDM is not upgrade ready. Exiting...")

    if post_deploy:
        expected_version = target_ver or version
        if version == expected_version:
            print(f"---> PPDM is operational on version {version}")
            return True
        raise SystemExit("Post-upgrade version checks failed. Exiting...")

    print("---> PPDM is upgrade ready")
    return version


def perform_version_checks(ppdm_uri, token, current_ver, ppdm_release, upg_file):
    """Performs pre-upgrade version and upgrade package validations"""
    if ppdm_release:
        print("---> Checking upgrade to PPDM version:", ppdm_release)
        if current_ver == ppdm_release:
            raise SystemExit("Current PPDM version is identical to the intended version. Exiting...")
        query = f'packageVersion eq "{ppdm_release}" and category eq "ACTIVE"'
    else:
        file_name = os.path.basename(upg_file)
        try:
            target_ver = file_name.split("-sw-")[1].rsplit('.', 1)[0]
        except IndexError as error:
            raise SystemExit("Invalid upgrade file format.") from error
        print("---> Checking upgrade to PPDM version:", target_ver)
        if current_ver == target_ver:
            raise SystemExit("Current PPDM version is identical to the intended version. Exiting...")

    query = f'packageVersion eq "{target_ver}" and category eq "ACTIVE"'
    upg_uri = f"{ppdm_uri}/upgrade-packages"
    params = {"filter": query}
    response = init_rest_call("GET", upg_uri, token, None, params)

    try:
        return response["content"][0]
    except (IndexError, KeyError):
        query = 'category eq "ACTIVE"'
        params = {"filter": query}
        response = init_rest_call("GET", upg_uri, token, None, params)
        if response.get("content"):
            print(
                "At least one upgrade package of a different version already exists - remove it and retry. Exiting..."
            )
            raise SystemExit(1)
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
    print(
        f"---> Upload completed successfully in {time_diff // 60} mins "
        f"and {time_diff % 60} secs")
    return response.json()


def monitor_preupg_activity(ppdm_uri, token, upg_id, upg_timeout):
    """Monitors pre-upgrade tasks"""
    upgrade_uri = f"{ppdm_uri}/upgrade-packages/{upg_id}"
    poll_interval = 5
    start_time = time.time()

    print(f"-> Monitoring upgrade ID {upg_id}")

    while True:
        if (time.time() - start_time) > upg_timeout:
            break
        response = init_rest_call("GET", upgrade_uri, token)
        try:
            state = response["state"]
            if state in ("AVAILABLE", "INSTALLED"):
                print(f"---> Monitoring state {state}")
                return True
            if state == "PROCESSING":
                print(f"---> Monitoring state {state}")
            elif state in ("ERROR", "pre_check_FAILED"):
                print("-> Pre-check failed:")
                print(json.dumps(response, indent=4))
                return False
        except TypeError:
            pass
        time.sleep(poll_interval)

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
    upgrade_uri = f"{ppdm_uri}/upgrade-packages/{upg_data.get('id')}"
    params = {"forceUpgrade": "true"}
    upg_data["sizeInBytes"] = int(float(upg_data["sizeInBytes"]))

    response = init_rest_call("PUT", upgrade_uri, token, upg_data, params)

    if not response or "category" not in response:
        print("Upgrade request failed")
        return False

    if "category" in response:
        if response["category"] == "ACTIVE":
            return True

    return False


def check_ppdm_availability(ppdm_uri, username, password):
    """Checks if PPDM is available after a successfull upgrade"""
    max_attempts = 3
    wait_interval = 30

    for attempt in range(max_attempts):
        response = authenticate(ppdm_uri, username, password)
        if response:
            return response
        print(
            f"Attempt {attempt + 1}/{max_attempts} failed. "
            f"Retrying in {wait_interval}s..."
            )
        time.sleep(wait_interval)

    return False


def monitor_upg_activity(
    ppdm_uri, upg_token, monitor_timeout, post_deploy=None
):
    """Continuously monitors PPDM upgrade operations"""
    ppdm_uri = f"{ppdm_uri}/upgrade/status"
    poll_interval = 20
    retry_timeout = 600
    retry_interval = 40

    start = time.time()
    print("---> Monitoring PPDM upgrade")

    while True:
        if (time.time() - start) > monitor_timeout:
            break
        try:
            response = init_rest_call("GET", ppdm_uri, upg_token)
        except BaseException:
            time.sleep(retry_interval)
            response = init_rest_call("GET", ppdm_uri, upg_token)

        start_time = time.time()
        while not response:
            print("---> Polling timed out, retrying...")
            time.sleep(retry_interval)
            response = init_rest_call("GET", ppdm_uri, upg_token)
            if (time.time() - start_time) > retry_timeout:
                print("Timed out waiting for upgrade to complete. Exiting...")
                raise SystemExit(1)
            if post_deploy:
                return "TIMEOUT"

        upg_state = response[0]
        status = upg_state.get("upgradeStatus")
        stage = upg_state.get("currentStage")

        if status == "RUNNING":
            print(f"---> Upgrade status: {status} {upg_state['percentageCompleted']}%")
            print(f"----> Current component: {stage['component']}, "
                  f"description: {stage['description']} "
                  f"{stage['percentageCompleted']}%")
            print(f"----> Seconds elapsed / remaining: "
                  f"{upg_state['elapsedTime']} / {upg_state['estimatedRemainingTime']}")

        elif status == "PENDING":
            print(f"---> Upgrade status: {status}")

        elif status == "COMPLETED":
            print(f"---> Upgrade status: {status} {upg_state['percentageCompleted']}%")
            elapsed = upg_state['elapsedTime']
            print(f"--> Upgrade completed in {elapsed // 60} mins and {elapsed % 60} secs")
            return True

        elif status == "FAILED":
            print("---> PPDM Upgrade FAILED")
            print(f"----> Failed component: {stage.get('component')}, "
                  f"description: {stage.get('description')}")
            return False

        time.sleep(poll_interval)

    return False


def main():
    # Extract arguments
    args = get_args()

    server = args.server
    username, password = args.username, args.password
    upg_file, ppdm_release = args.upg_file, args.ppdm_release
    pre_check, skip_upload = args.pre_check, args.skip_upload
    skip_snapshot, just_monitor = args.skip_snapshot, args.just_monitor

    # Constants
    api_endpoint = "/api/v2"
    api_port = 8443
    upg_port = 14443
    upg_timeout = 3600
    upg_token = "abcdefghijklmn"
    baremetal_check = "GENERIC"

    # Validate Arguments
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

    # Getting PPDM configuration
    print("-> Obtaining PPDM configuration information")
    check_deployment_type(ppdm_uri, token, baremetal_check)
    current_ver = check_deployment(ppdm_uri, token)

    # Pre-upgrade checks
    print("-> Performing pre-upgrade version checks")
    print("---> Current PPDM version:", current_ver)

    version_checks = perform_version_checks(
        ppdm_uri, token, current_ver, ppdm_release, upg_file
    )

    # Handle monitoring-only mode
    if just_monitor:
        if upg_file or skip_upload or ppdm_release:
            print("---> Ignoring parmaters because only-monitor is specified")
        print(
            "-> only-monitor parameter provided. Monitoring currently running upgrade."
        )
        upg_uri = "https://{server}:{upg_port}"
        result = monitor_upg_activity(
            upg_uri, upg_token, upg_timeout, True
        )

        if result is True:
            print("-> PPDM upgraded successfully")
        elif result is False:
            print("-> PPDM upgrade failed")
            raise SystemExit(1)

        print("-> Making sure PPDM is up and running")
        token = check_ppdm_availability(ppdm_uri, username, password)
        if token:
            print("---> PPDM is available")
            check_deployment(ppdm_uri, token, True)
            raise SystemExit(0)

        raise SystemExit("---> PPDM is not available yet, check again later...")

    # Upload or reuse upgrade package
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

    upg_pkg_id = upg_data["id"]

    # Monitor pre-upgrade tasks
    monitor_preupg_activity(ppdm_uri, token, upg_pkg_id, upg_timeout)

    # Execute and monitor pre-check
    print("-> Performing pre-upgrade checks")
    perform_pre_check(ppdm_uri, token, upg_pkg_id)
    if not monitor_preupg_activity(ppdm_uri, token, upg_pkg_id, upg_timeout):
        raise SystemExit(1)

    if pre_check:
        print("---> Pre-check parameter provided. Exiting")
        raise SystemExit(0)

    # Upgrade PPDM
    print("-> Upgrading PPDM to release", upg_data["packageVersion"])

    if skip_snapshot:
        upg_data["skipSnapshot"] = True

    if not check_hosting_vcenter(ppdm_uri, token):
        print(
            "---> Skipping PPDM VM snapshot because hosting vCenter is not configured"
        )
        upg_data["skipSnapshot"] = True

    # Prepare upgrade payload
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
            print("-> PPDM upgraded successfully")
        else:
            print("-> PPDM upgrade failed")
            raise SystemExit(1)
    else:
        print("-> PPDM upgrade failed")
        raise SystemExit(1)

    # Post-upgrade validation
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
