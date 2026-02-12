#!/usr/bin/env python3

"""
PowerProtect Data Manager Lifecycle Management Script.

Automates PPDM lifecycle management including package upload, validation,
execution, monitoring, and health checks.

Author: Idan Kentor <idan.kentor@dell.com>

Copyright: Copyright [2026] [Idan Kentor]

Example usage:
    python ppdm_upgrade.py -s 10.0.0.1 -p "password" \
      -f dellemc-ppdm-upgrade-sw-19.22.0-24.pkg

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      -f dellemc-ppdm-upgrade-sw-19.22.0-24.pkg

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      -skipupload -release 19.19.0

    python ppdm_upgrade.py -s 10.0.0.1 -p "password" \
      -f dellemc-ppdm-upgrade-sw-19.22.0-24.pkg -onlyprecheck

    python ppdm_upgrade.py -s 10.0.0.1 -p "password" \
      -f dellemc-ppdm-upgrade-sw-19.22.0-24.pkg -skipsnapshot

    python ppdm_upgrade.py -s 10.0.0.1 -p "password" -onlymonitor

    python ppdm_upgrade.py -s 10.0.0.1 -p "password" -skipupload \
      -release 19.22.0-24
"""

import argparse
import datetime
import json
import logging
import logging.handlers
import os
import sys
import time
import urllib3
import requests

urllib3.disable_warnings()

logger = logging.getLogger("ppdm_upgrade")


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
        help="PPDM password",
    )

    parser.add_argument(
        "-envpassword", "--env-password",
        dest="env_password",
        action="store_true",
        help="Read password from PPDM_PASSWORD environment variable",
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

    parser.add_argument(
        "-log", "--log-file",
        default="ppdm_upgrade.log",
        help="Log file path (default: ppdm_upgrade.log)"
    )

    args = parser.parse_args()
    return args


def setup_logger(log_file):
    """Configure logging to file only and log execution start"""
    max_bytes = 10 * 1024 * 1024  # 10MB
    log_backup_count = 5

    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=log_backup_count
        )
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - "
            "%(funcName)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        separator = "=" * 80
        logger.info(separator)
        logger.info("PPDM Upgrade Script Started")
        logger.info("Execution Time: %s",
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("Script: PowerProtect Data Manager Upgrade Automation")
        for i, arg in enumerate(sys.argv):
            if arg == "-p" and i + 1 < len(sys.argv):
                sys.argv[i + 1] = "*** REDACTED ***"
            elif arg.startswith("--password="):
                sys.argv[i] = "--password=*** REDACTED ***"
        logger.info("Command: %s", " ".join(sys.argv))
        logger.info(separator)
    except (OSError, IOError) as error:
        print(f"-> Could not create log file: {error}")

    return logger


def log_response_summary(verb, uri, response):
    """Brief response logging for debugging"""
    if verb.lower() != "get":
        return

    try:
        content = response.text
        preview = content[:300].rstrip()
        if len(content) >= 300:
            preview += "..."
        logger.info(
            "GET %s: %d bytes - %s",
            uri, len(response.content), preview
        )
    except Exception:
        logger.info("GET %s: %d bytes (non-text)", uri, len(response.content))


def sanitize_payload_for_logging(payload_str, uri):
    """Sanitize sensitive information from payloads for logging"""
    if uri.endswith("/login") and payload_str:
        return "*** REDACTED ***"

    if not payload_str:
        return payload_str
    preview = payload_str[:300].rstrip()
    if len(payload_str) >= 300:
        preview += "..."

    return preview


def init_rest_call(verb, uri, token, payload=None, params=None):
    """Generic function for REST calls"""
    verify = False
    monitor = False
    timeout = 90
    code = {200, 201, 202, 204}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    payload_str = json.dumps(payload) if payload is not None else None

    logger.info(
        "REST Call: %s %s, Params: %s, Payload: %s", verb, uri,
        params, sanitize_payload_for_logging(payload_str, uri)
    )

    if uri.endswith("/login"):
        headers = {"Content-Type": "application/json"}
    elif uri.endswith("/upgrade/status"):
        headers.update({"Authorization": f"{token}"})
        monitor = True

    response = None
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
                data=payload_str,
                verify=verify,
                timeout=timeout,
            )
        response.raise_for_status()
    except requests.exceptions.Timeout as error:
        print(f"-> Connection timed out: {uri}")
        error = error.args[0] if error.args else error
        logger.error(
            "Connection timed out: %s - %s",
            uri, error
        )
        return False
    except requests.exceptions.ConnectionError as error:
        if not monitor:
            error = error.args[0] if error.args else error
            print(f"-> Error connecting to {uri}: {error}")
            logger.error("Connection error: %s - %s", uri, error)
        return False
    except requests.exceptions.RequestException as error:
        if not response:
            logger.error(
                "REST call failed: %s %s - No response - Exception: %s",
                verb, uri, str(error)
            )
            return False
        if response.status_code in (401, 502):
            logger.error(
                "REST call failed: %s %s - Status %d",
                verb, uri, response.status_code
            )
            return False
        print(
            f"-> The call {response.request.method} {response.url} "
            f"failed with exception:{error}"
        )
        logger.error(
            "REST call failed: %s %s - Status %d - Exception: %s",
            response.request.method, response.url,
            response.status_code, error
        )

    if response.status_code not in code:
        raise requests.exceptions.HTTPError(
            f"-> Failed to query {uri}, code: {response.status_code}, "
            f"body: {response.text}"
        )

    logger.info(
        "REST call successful: %s %s, status: %d, time: %.3fs",
        verb, uri, response.status_code, response.elapsed.total_seconds()
    )

    if not response.content:
        logger.debug(
            "Empty response content for %s %s",
            verb, uri
        )
        return True

    log_response_summary(verb, uri, response)

    if uri.endswith("/login"):
        return response.json()["access_token"]

    try:
        return response.json()
    except ValueError:
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
        raise SystemExit(
            f"---> Solution is not supported on {deploy_type}. Exiting..."
        )

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
            raise SystemExit(
                "Cannot query the Data Manager server. Exiting..."
            )

    ppdm_node = nodes["content"][0]
    status = ppdm_node.get("status")
    version = ppdm_node.get("version")

    if status != "OPERATIONAL_RUNNING":
        if post_deploy:
            raise SystemExit(
                f"PPDM is on version {version} but with "
                f"state {status}. Exiting..."
            )
        raise SystemExit(
            "PPDM is not upgrade ready. Exiting..."
        )

    if post_deploy:
        expected_version = target_ver or version
        if version == expected_version:
            print(f"---> PPDM is operational on version {version}")
            return True
        raise SystemExit(
            "Post-upgrade version checks failed. Exiting..."
        )

    print("---> PPDM is upgrade ready")
    return version


def perform_version_checks(
    ppdm_uri, token, current_ver, ppdm_release, upg_file
):
    """Performs pre-upgrade version and upgrade package validations"""
    if ppdm_release:
        target_ver = ppdm_release
    else:
        file_name = os.path.basename(upg_file)
        try:
            target_ver = file_name.split("-sw-")[1].rsplit('.', 1)[0]
        except IndexError as error:
            raise SystemExit("Invalid upgrade file format.") from error

    print("---> Checking upgrade to PPDM version:", target_ver)
    if current_ver == target_ver:
        raise SystemExit(
            "Current PPDM version is identical to the "
            "intended version. Exiting..."
        )

    query = f'packageVersion eq "{target_ver}" and category eq "ACTIVE"'
    upg_uri = f"{ppdm_uri}/upgrade-packages"
    params = {"filter": query}
    response = init_rest_call("GET", upg_uri, token, None, params)

    try:
        return response["content"][0]
    except (IndexError, KeyError, TypeError):
        query = 'category eq "ACTIVE"'
        params = {"filter": query}
        response = init_rest_call("GET", upg_uri, token, None, params)
        if response.get("content"):
            existing_ver = response["content"][0].get(
                "packageVersion", "unknown"
            )
            print(
                f"Upgrade package version {existing_ver} already exists "
                f"but does not match target {target_ver}. "
                "Remove it and retry. Exiting..."
            )
            logger.error(
                "Upgrade package version mismatch: "
                "existing=%s, target=%s",
                existing_ver, target_ver
            )
            raise SystemExit(1)
        return False


def check_hosting_vcenter(ppdm_uri, token):
    """Checks if there is a vCenter configured as hosting"""
    ppdm_uri = f"{ppdm_uri}/inventory-sources"
    query = (
        'type eq "VCENTER" and details.vCenter.hosting eq true '
        'and details.vCenter.internal eq false'
    )
    params = {"filter": query}

    response = init_rest_call("GET", ppdm_uri, token, None, params)

    if not response or "content" not in response:
        return False

    return len(response["content"]) == 1


def multipart_encoder(upg_file, boundary):
    """Yields multipart form data in chunks"""
    file_name = os.path.basename(upg_file)
    chunk_size = 8192

    yield f'--{boundary}\r\n'.encode()
    yield (
        f'Content-Disposition: form-data; name="file"; '
        f'filename="{file_name}"\r\n'.encode()
    )
    yield b'Content-Type: application/octet-stream\r\n\r\n'

    with open(upg_file, 'rb') as file_handle:
        while chunk := file_handle.read(chunk_size):
            yield chunk
    yield f'\r\n--{boundary}--\r\n'.encode()


def upload_package(ppdm_uri, token, upg_file):
    """Uploads upgrade package to PPDM using custom multipart encoder"""
    try:
        logger.info(
            "Starting upgrade package upload: %s",
            os.path.basename(upg_file)
        )
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
        logger.error("Could not open upgrade package: %s", error)
        raise SystemExit(1) from error
    except MemoryError as error:
        print(
            "Package upload failed due to insufficient "
            "memory/disk space. Exiting..."
        )
        logger.error(
            "Package upload failed due to insufficient memory/disk space"
        )
        raise SystemExit(1) from error

    if response.status_code != 201:
        print("Package upload failed, exiting...")
        logger.error(
            "Package upload failed with status code: %d", response.status_code
        )
        raise SystemExit(1)

    time_diff = round(end_time - start_time)
    print(
        f"---> Upload completed successfully in {time_diff // 60} mins "
        f"and {time_diff % 60} secs"
    )
    logger.info(
        "Upload completed successfully in %d mins %d secs",
        time_diff // 60, time_diff % 60
    )
    return response.json()


def monitor_preupg_activity(ppdm_uri, token, upg_id, upg_timeout):
    """Monitors pre-upgrade tasks"""
    upgrade_uri = f"{ppdm_uri}/upgrade-packages/{upg_id}"
    poll_interval = 5
    start_time = time.monotonic()

    print(f"-> Monitoring upgrade ID {upg_id}")

    while True:
        if (time.monotonic() - start_time) > upg_timeout:
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
                logger.error("Pre-check failed: %s", json.dumps(response))
                return False
        except TypeError:
            pass
        time.sleep(poll_interval)

    return False


def authenticate(ppdm_uri, username, password):
    """Login"""
    ppdm_uri = f"{ppdm_uri}/login"
    login_payload = {"username": username, "password": password}

    logger.info("Attempting login to PPDM API")
    token = init_rest_call("POST", ppdm_uri, login_payload, login_payload)

    if token:
        logger.info("Login successful")
    else:
        logger.error("Login failed")

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
        logger.error("Upgrade request failed - no category in response")
        return False

    return response["category"] == "ACTIVE"


def check_ppdm_availability(ppdm_uri, username, password):
    """Checks if PPDM is available after a successful upgrade"""
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

    monitor_start = time.monotonic()
    print("---> Monitoring PPDM upgrade")

    while True:
        if (time.monotonic() - monitor_start) > monitor_timeout:
            break
        try:
            response = init_rest_call("GET", ppdm_uri, upg_token)
        except Exception:
            time.sleep(retry_interval)
            response = init_rest_call("GET", ppdm_uri, upg_token)

        retry_start = time.monotonic()
        while not response:
            if (time.monotonic() - monitor_start) > monitor_timeout:
                print("Timed out waiting for upgrade to complete. Exiting...")
                logger.error("Timed out waiting for upgrade to complete")
                raise SystemExit(1)
            if (time.monotonic() - retry_start) > retry_timeout:
                if post_deploy:
                    return "TIMEOUT"
                print("Timed out waiting for upgrade to complete. Exiting...")
                logger.error("Timed out waiting for upgrade to complete")
                raise SystemExit(1)
            logger.info(
                "Upgrade status unavailable, retrying in %ds", retry_interval
            )
            print("---> Polling timed out, retrying...")
            time.sleep(retry_interval)
            response = init_rest_call("GET", ppdm_uri, upg_token)

        if not isinstance(response, (list, tuple)):
            print("---> No upgrade status available")
            logger.error("Invalid response type: %s", type(response))
            return False

        upg_state = response[0]
        status = upg_state.get("upgradeStatus")
        stage = upg_state.get("currentStage")

        if status == "RUNNING":
            print(
                f"---> Upgrade status: {status} "
                f"{upg_state['percentageCompleted']}%"
            )
            print(f"----> Current component: {stage['component']}, "
                  f"description: {stage['description']}, "
                  f"progress: {stage['percentageCompleted']}%")
            print(
                f"----> Seconds elapsed / remaining: "
                f"{upg_state['elapsedTime']} / "
                f"{upg_state['estimatedRemainingTime']}"
            )

        elif status == "PENDING":
            print(f"---> Upgrade status: {status}")

        elif status == "COMPLETED":
            print(
                f"---> Upgrade status: {status} "
                f"{upg_state['percentageCompleted']}%"
            )
            elapsed = upg_state['elapsedTime']
            print(
                f"--> Upgrade completed in {elapsed // 60} mins "
                f"and {elapsed % 60} secs"
            )
            return True

        elif status == "FAILED":
            print("---> PPDM Upgrade FAILED")
            print(f"----> Failed component: {stage.get('component')}, "
                  f"description: {stage.get('description')}")
            logger.error(
                "PPDM upgrade failed - component: %s, description: %s",
                stage.get('component'), stage.get('description')
            )
            return False

        time.sleep(poll_interval)

    return False


def main():
    # Extract arguments
    args = get_args()

    # Initialize logger (includes execution start logging)
    setup_logger(args.log_file)

    server = args.server
    username = args.username

    # Get password from a command line argument or environment variable
    if args.password:
        password = args.password
    elif args.env_password:
        password = os.environ.get("PPDM_PASSWORD")
        if not password:
            print("PPDM_PASSWORD environment variable is not set. Exiting...")
            logger.error("PPDM_PASSWORD environment variable is not set")
            raise SystemExit(1)
    else:
        print("Password is required. Use -p or -envpassword. Exiting...")
        logger.error("Password not provided")
        raise SystemExit(1)

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
            "The PPDM release must be provided when skipping package upload. "
            "Exiting..."
        )
        logger.error(
            "PPDM release must be provided when skipping package upload"
        )
        raise SystemExit(1)

    if ppdm_release and not skip_upload:
        if upg_file:
            print(
                "---> Ignoring 'ppdm-release' parameter as it "
                "requires 'skip-file-upload'"
            )
            ppdm_release = None
        else:
            print(
                "Upgrade package and 'skip-upload' parameters "
                "were not specified. Exiting..."
            )
            logger.error(
                "Upgrade package and skip-upload parameters not specified"
            )
            raise SystemExit(1)

    if just_monitor:
        if upg_file or skip_upload:
            print("---> Ignoring parameters because only-monitor is specified")
            logger.info(
                "Ignoring parameters because only-monitor is specified"
            )
        print(
            "-> only-monitor parameter provided. "
            "Monitoring currently running upgrade."
        )

        logger.info("Starting monitor-only mode for upgrade monitoring")
        ppdm_uri = f"https://{server}:{api_port}{api_endpoint}"
        token = authenticate(ppdm_uri, username, password)

        if token:
            current_ver = check_deployment(ppdm_uri, token)
            print(f"---> PPDM is responsive, version: {current_ver}")
            if ppdm_release and current_ver == ppdm_release:
                print("-> PPDM already at target version")
                raise SystemExit(0)
            print("---> Proceeding to upgrade monitoring")
            logger.info("Proceeding to upgrade monitoring")

        upg_uri = f"https://{server}:{upg_port}"
        result = monitor_upg_activity(
            upg_uri, upg_token, upg_timeout, True
        )

        if result is True:
            print("-> PPDM upgraded successfully")
            logger.info("PPDM upgrade completed successfully")
            raise SystemExit(0)
        elif result is False:
            print("-> PPDM upgrade failed")
            logger.error("PPDM upgrade failed")
            raise SystemExit(1)
        else:
            print("-> PPDM upgrade timed out")
            logger.error("PPDM upgrade monitoring timed out")
            raise SystemExit(1)

    if not upg_file and not ppdm_release and not skip_upload:
        print(
            "Need to specify either upgrade file or skip-upload. Exiting..."
        )
        logger.error(
            "Need to specify upgrade file or skip-upload"
        )
        raise SystemExit(1)

    # Logs into the PPDM API
    ppdm_uri = f"https://{server}:{api_port}{api_endpoint}"
    logger.info("Authenticating to PPDM API: %s", server)
    token = authenticate(ppdm_uri, username, password)
    if not token:
        print("-> Login failed")
        raise SystemExit(1)

    # Getting PPDM configuration
    print("-> Obtaining PPDM configuration information")
    logger.info("Obtaining PPDM configuration")
    check_deployment_type(ppdm_uri, token, baremetal_check)
    current_ver = check_deployment(ppdm_uri, token)

    # Pre-upgrade checks
    print("-> Performing pre-upgrade version checks")
    logger.info("Performing pre-upgrade version checks")
    print("---> Current PPDM version:", current_ver)
    logger.info("Current PPDM version: %s", current_ver)

    version_checks = perform_version_checks(
        ppdm_uri, token, current_ver, ppdm_release, upg_file
    )

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
                "---> File upload skipped as a package of the same release "
                "already exists"
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
            "---> Skipping PPDM VM snapshot because hosting vCenter "
            "is not configured"
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
            logger.error("PPDM upgrade failed in main execution path")
            raise SystemExit(1)
    else:
        print("-> PPDM upgrade failed")
        logger.error("PPDM upgrade failed - result was False")
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
