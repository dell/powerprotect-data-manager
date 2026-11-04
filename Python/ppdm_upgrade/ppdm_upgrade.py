#!/usr/bin/env python3

"""
PowerProtect Data Manager Lifecycle Management Script.

Automates PPDM lifecycle management including package download from URL,
package upload, validation, execution, monitoring, and health checks.

Author: Idan Kentor <idan.kentor@dell.com>

Version 7 - October 2026

Copyright: [2026] [Idan Kentor]

Example usage:
    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      -f dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg

    python ppdm_upgrade.py -s 10.0.0.1 -p "password" \
      -f dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      --url https://server/path/dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      --url https://server/path/dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg \
      --download-user myuser --download-password "mypass"

    export PPDM_DOWNLOAD_USER=myuser PPDM_DOWNLOAD_PASSWORD="mypass"
    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      --url https://server/path/dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      --url https://server/path/dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg \
      --download-user myuser --download-password "mypass" \
      --download-dir /tmp/packages

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      -skipupload -release 20.3.0

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      -f dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg -onlyprecheck

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      -f dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg -skipsnapshot

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword -onlymonitor

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword -skipupload \
      -release 20.3.0.10-11

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      -f dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg -tls

    python ppdm_upgrade.py -s 10.0.0.1 -envpassword \
      --url https://server/path/dellemc-ppdm-upgrade-sw-20.3.0.10-11.pkg \
      -tls
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

logger = logging.getLogger("ppdm_upgrade")


def get_args():
    """Gets command line args from the user"""
    parser = argparse.ArgumentParser(
        description="Automate PowerProtect Data Manager lifecycle management",
        allow_abbrev=False
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
        "-url", "--url",
        dest="download_url",
        help="URL to download the upgrade package from",
    )

    parser.add_argument(
        "-down-user", "--download-user",
        dest="download_user",
        help="Username for URL download (or set PPDM_DOWNLOAD_USER env var)",
    )

    parser.add_argument(
        "-down-pass", "--download-password",
        dest="download_password",
        help="Password for URL download (or PPDM_DOWNLOAD_PASSWORD env var)",
    )

    parser.add_argument(
        "-down-dir", "--download-dir",
        dest="download_dir",
        help="Directory to save the downloaded package (default: current dir)",
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
        "-tls", "--verify-cert",
        dest="verify_cert",
        action="store_true",
        default=False,
        help="Enable TLS certificate verification",
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
        secret_flags = {
            "-p", "--password", "-down-pass", "--download-password"
        }
        redacted_argv = list(sys.argv)
        for index in range(len(redacted_argv)):
            argument = redacted_argv[index]
            if "://" in argument and "@" in argument.split("://", 1)[1]:
                scheme, rest = argument.split("://", 1)
                credentials, host_path = rest.split("@", 1)
                if ":" in credentials and "/" not in credentials:
                    redacted_argv[index] = (
                        f"{scheme}://*** REDACTED ***@{host_path}"
                    )
            flag = redacted_argv[index].split("=")[0]
            if flag in secret_flags and "=" in redacted_argv[index]:
                redacted_argv[index] = f"{flag}=*** REDACTED ***"
            elif flag in secret_flags and index + 1 < len(redacted_argv):
                redacted_argv[index + 1] = "*** REDACTED ***"
        logger.info("Command: %s", " ".join(redacted_argv))
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
    except ValueError:
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


def init_rest_call(verb, uri, token, payload=None, params=None, verify=False):
    """Generic function for REST calls"""
    monitor = False
    timeout = 90
    code = {200, 201, 202, 204}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    payload_str = json.dumps(payload) if payload != None else None

    logger.info(
        "REST Call: %s %s, Verify: %s, Params: %s, Payload: %s", verb, uri,
        verify, params, sanitize_payload_for_logging(payload_str, uri)
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


def check_deployment_type(ppdm_uri, token, bm_check, verify=False):
    """Validates that PPDM deployment type"""
    config_uri = f"{ppdm_uri}/configurations"
    config = init_rest_call("GET", config_uri, token, verify=verify)

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


def check_deployment(
    ppdm_uri, token, post_deploy=None, target_ver=None, verify=False
):
    """Validates that PPDM is ready for upgrade and healthy post-upgrade"""
    nodes_uri = f"{ppdm_uri}/nodes"
    retry_interval = 60
    nodes = init_rest_call("GET", nodes_uri, token, verify=verify)

    if not nodes or not isinstance(nodes, dict) or "content" not in nodes:
        time.sleep(retry_interval)
        nodes = init_rest_call("GET", nodes_uri, token, verify=verify)
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
    ppdm_uri, token, current_ver, ppdm_release, upg_file, verify=False
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
    response = init_rest_call(
        "GET", upg_uri, token, None, params, verify=verify
    )

    try:
        return response["content"][0]
    except (IndexError, KeyError, TypeError):
        query = 'category eq "ACTIVE"'
        params = {"filter": query}
        response = init_rest_call(
            "GET", upg_uri, token, None, params, verify=verify
        )
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


def check_hosting_vcenter(ppdm_uri, token, verify=False):
    """Checks if there is a vCenter configured as hosting"""
    ppdm_uri = f"{ppdm_uri}/inventory-sources"
    query = (
        'type eq "VCENTER" and details.vCenter.hosting eq true '
        'and details.vCenter.internal eq false'
    )
    params = {"filter": query}

    response = init_rest_call(
        "GET", ppdm_uri, token, None, params, verify=verify
    )

    if not response or "content" not in response:
        return False

    return len(response["content"]) == 1


def print_progress_bar(current, total, start_time, prefix="Progress"):
    """Prints a text-based progress bar with speed and ETA."""
    if total <= 0:
        return

    percent = (current / total) * 100
    elapsed = time.time() - start_time
    speed = current / elapsed if elapsed > 0 else 0
    speed_mb = speed / (1024 * 1024)
    remaining = (total - current) / speed if speed > 0 else 0
    bar_length = 40
    filled = int(bar_length * current / total)
    bar = "=" * filled + "-" * (bar_length - filled)
    current_mb = current / (1024 * 1024)
    total_mb = total / (1024 * 1024)

    print(
        f"\r  {prefix}: [{bar}] {percent:.1f}%  "
        f"{current_mb:.1f}/{total_mb:.1f} MB  "
        f"{speed_mb:.2f} MB/s  ETA: {int(remaining)}s   ",
        end="", flush=True
    )


def download_package(
    url, download_dir, username=None, password=None, verify=False
):
    """Downloads upgrade package from URL with optional Basic authentication"""
    max_attempts = 3
    chunk_size = 65536
    retry_wait = 5

    file_name = url.split("/")[-1].split("?")[0]
    if not file_name.endswith(".pkg"):
        print("The URL must end with the .pkg file name. Exiting...")
        logger.error("URL does not end with a .pkg file name")
        raise SystemExit(1)

    if download_dir != None:
        download_path = os.path.join(download_dir, file_name)
    else:
        download_path = file_name

    download_path = os.path.abspath(download_path)

    auth = None
    if username != None and password != None:
        auth = (username, password)

    log_url = url
    if "://" in url and "@" in url.split("://", 1)[1]:
        scheme, rest = url.split("://", 1)
        credentials, host_path = rest.split("@", 1)
        if ":" in credentials and "/" not in credentials:
            log_url = f"{scheme}://*** REDACTED ***@{host_path}"

    logger.info("Starting download from: %s (TLS verify=%s)", log_url, verify)
    logger.info("Download destination: %s", download_path)

    for attempt in range(max_attempts):
        start_time = time.time()
        try:
            print(
                f"---> Downloading package "
                f"(attempt {attempt + 1}/{max_attempts})"
            )
            with requests.get(
                url, auth=auth, stream=True, verify=verify, timeout=30
            ) as response:
                response.raise_for_status()
                total_size = int(response.headers.get("content-length", 0))
                downloaded = 0
                last_step = -1
                if total_size == 0:
                    print("---> No Content-Length header, size not verified")
                    logger.warning("No Content-Length, size not verified")
                with open(download_path, "wb") as file_handle:
                    for chunk in response.iter_content(chunk_size=chunk_size):
                        if chunk:
                            file_handle.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                step = downloaded * 1000 // total_size
                                if step != last_step:
                                    print_progress_bar(
                                        downloaded, total_size, start_time,
                                        "Download"
                                    )
                                    last_step = step
            print()
            actual_size = os.path.getsize(download_path)
            if total_size > 0 and actual_size != total_size:
                logger.error(
                    "Download size mismatch: expected %d, got %d",
                    total_size, actual_size
                )
                raise IOError(
                    f"Downloaded size ({actual_size}) != "
                    f"Content-Length ({total_size})"
                )
            time_diff = round(time.time() - start_time)
            print(
                f"---> Download completed in {time_diff // 60} mins "
                f"and {time_diff % 60} secs"
            )
            logger.info(
                "Download completed: %s (%d bytes)", download_path, actual_size
            )
            return download_path
        except (requests.exceptions.RequestException, IOError) as error:
            error_text = str(error).replace(url, log_url)
            logger.error(
                "Download attempt %d failed: %s", attempt + 1, error_text
            )
            if os.path.exists(download_path) == True:
                try:
                    os.remove(download_path)
                except OSError:
                    pass
            if attempt < max_attempts - 1:
                print(
                    f"-> Download attempt failed: {error_text}. "
                    f"Retrying in {retry_wait}s..."
                )
                time.sleep(retry_wait)
            else:
                print("-> Download failed after all attempts. Exiting...")
                raise SystemExit(1) from error

    return None


def multipart_encoder(upg_file, header, trailer):
    """Yields multipart form data in chunks with progress bar"""
    chunk_size = 65536
    file_size = os.path.getsize(upg_file)

    uploaded = 0
    last_step = -1
    start_time = time.time()

    yield header

    with open(upg_file, 'rb') as file_handle:
        while chunk := file_handle.read(chunk_size):
            yield chunk
            uploaded = uploaded + len(chunk)
            step = uploaded * 1000 // file_size
            if step != last_step:
                print_progress_bar(uploaded, file_size, start_time, "Upload")
                last_step = step

    print()

    yield trailer


def upload_package(ppdm_uri, token, upg_file, verify=False):
    """Uploads upgrade package to PPDM using custom multipart encoder"""
    try:
        print(f"---> Starting upgrade package upload: {upg_file}")
        logger.info(
            "Starting upgrade package upload: %s (TLS verify=%s)",
            os.path.basename(upg_file),
            verify
        )
        boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
        header = (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="file"; '
            f'filename="{os.path.basename(upg_file)}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n'
        ).encode()
        trailer = f'\r\n--{boundary}--\r\n'.encode()
        body_size = len(header) + os.path.getsize(upg_file) + len(trailer)

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(body_size)
        }
        ppdm_uri = f"{ppdm_uri}/upgrade-packages"

        start_time = time.time()
        prepared = requests.Request(
            "POST",
            ppdm_uri,
            headers=headers,
            data=multipart_encoder(upg_file, header, trailer)
        ).prepare()
        prepared.headers.pop("Transfer-Encoding")
        response = requests.Session().send(
            prepared,
            timeout=90,
            verify=verify
        )
        end_time = time.time()
    except IOError as error:
        print(f"Package upload failed: {error}. Exiting...")
        logger.error("Package upload failed: %s", error)
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
        print(f"Package upload failed: {response.text[:300]}. Exiting...")
        logger.error(
            "Package upload failed with status code: %d, body: %s",
            response.status_code, response.text[:300]
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


def monitor_preupg_activity(
    ppdm_uri, token, upg_id, upg_timeout, verify=False
):
    """Monitors pre-upgrade tasks"""
    upgrade_uri = f"{ppdm_uri}/upgrade-packages/{upg_id}"
    poll_interval = 5
    retry_timeout = 600
    retry_interval = 10
    start_time = time.monotonic()

    print(f"-> Monitoring upgrade ID {upg_id}")

    while True:
        elapsed = time.monotonic() - start_time
        if elapsed > upg_timeout:
            print("Pre-check timeout exceeded. Exiting...")
            logger.error(
                "Pre-check timeout exceeded (%d seconds)", upg_timeout
            )
            return False
        response = init_rest_call("GET", upgrade_uri, token, verify=verify)
        retry_start = time.monotonic()
        while not response:
            if (time.monotonic() - start_time) > upg_timeout:
                print("Timed out waiting for pre-check. Exiting...")
                logger.error("Timed out waiting for pre-check")
                return False
            if (time.monotonic() - retry_start) > retry_timeout:
                print("Pre-check monitoring timed out. Exiting...")
                logger.error("Pre-check retry timeout exceeded")
                return False
            logger.info(
                "Pre-check status unavailable, retrying in %ds",
                retry_interval
            )
            print("---> Polling timed out, retrying...")
            time.sleep(retry_interval)
            response = init_rest_call("GET", upgrade_uri, token, verify=verify)
        if not isinstance(response, dict):
            time.sleep(poll_interval)
            continue
        precheck_state = response.get("precheckState")
        if precheck_state:
            if precheck_state == "FAILED":
                print("-> Pre-check FAILED. Exiting...")
                logger.error("Pre-check failed with state: %s", precheck_state)
                return False
            if precheck_state == "COMPLETED":
                print("-> Pre-check COMPLETED successfully")
                logger.info("Pre-check completed successfully")
                return True
            if precheck_state in ("IN_PROGRESS", "PENDING"):
                print(
                    f"---> Pre-check {precheck_state} "
                    f"(elapsed: {int(elapsed)}s)"
                )
                logger.info("Pre-check %s", precheck_state)
                time.sleep(poll_interval)
                continue
        state = response.get("state", "UNKNOWN")
        if state in ("AVAILABLE", "INSTALLED"):
            print(f"---> Monitoring state {state}")
            return True
        if state == "PROCESSING":
            print(f"---> Monitoring state {state}")
        elif state in ("ERROR", "PRECHECK_FAILED", "pre_check_FAILED"):
            print(f"-> Pre-check failed: {response.get('errorMessage')}")
            for component in response.get("subComponentDetails", []):
                if component.get("subComponentUpgradeState") == "FAILED":
                    print(
                        f"---> {component.get('displayName')}: "
                        f"{component.get('errorMessage')}"
                    )
            logger.error("Pre-check failed: %s", json.dumps(response))
            return False
        time.sleep(poll_interval)


def authenticate(ppdm_uri, username, password, verify=False):
    """Login"""
    ppdm_uri = f"{ppdm_uri}/login"
    login_payload = {"username": username, "password": password}

    logger.info("Attempting login to PPDM API")
    token = init_rest_call(
        "POST", ppdm_uri, login_payload, login_payload, verify=verify
    )

    if token:
        logger.info("Login successful")
    else:
        logger.error("Login failed")

    return token


def perform_pre_check(ppdm_uri, token, upg_id, verify=False):
    """Executes pre-upgrade checks"""
    ppdm_uri = f"{ppdm_uri}/upgrade-packages/{upg_id}/precheck"

    response = init_rest_call("POST", ppdm_uri, token, verify=verify)
    return response


def upgrade_ppdm(ppdm_uri, token, upg_data, verify=False):
    """Upgrades PPDM"""
    upgrade_uri = f"{ppdm_uri}/upgrade-packages/{upg_data.get('id')}"
    params = {"forceUpgrade": "true"}
    upg_data["sizeInBytes"] = int(float(upg_data["sizeInBytes"]))

    response = init_rest_call(
        "PUT", upgrade_uri, token, upg_data, params, verify=verify
    )

    if not response or "category" not in response:
        print("Upgrade request failed")
        logger.error("Upgrade request failed - no category in response")
        return False

    return response["category"] == "ACTIVE"


def check_ppdm_availability(ppdm_uri, username, password, verify=False):
    """Checks if PPDM is available after a successful upgrade"""
    max_attempts = 3
    wait_interval = 30

    for attempt in range(max_attempts):
        response = authenticate(ppdm_uri, username, password, verify=verify)
        if response:
            return response
        print(
            f"Attempt {attempt + 1}/{max_attempts} failed. "
            f"Retrying in {wait_interval}s..."
        )
        time.sleep(wait_interval)

    return False


def monitor_upg_activity(
    ppdm_uri, upg_token, monitor_timeout, post_deploy=None, verify=False
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
            response = init_rest_call(
                "GET", ppdm_uri, upg_token, verify=verify
            )
        except requests.exceptions.RequestException:
            time.sleep(retry_interval)
            response = init_rest_call(
                "GET", ppdm_uri, upg_token, verify=verify
            )
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
            response = init_rest_call(
                "GET", ppdm_uri, upg_token, verify=verify
            )
        if not isinstance(response, (list, tuple)):
            print("---> No upgrade status available")
            logger.error("Invalid response type: %s", type(response))
            return False
        upg_state = response[0]
        status = upg_state.get("upgradeStatus")
        stage = upg_state.get("currentStage") or {}
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
            upg_error = upg_state.get("upgradeError") or {}
            print("---> PPDM Upgrade FAILED")
            print(f"----> Failed component: {stage.get('component')}, "
                  f"description: {stage.get('description')}")
            if upg_error:
                print(
                    f"----> {upg_error.get('messageID')} - "
                    f"{upg_error.get('reason')}"
                )
            logger.error(
                "PPDM upgrade failed - component: %s, description: %s",
                stage.get('component'), stage.get('description')
            )
            logger.error("PPDM upgrade status: %s", json.dumps(upg_state))
            return False
        time.sleep(poll_interval)

    return "TIMEOUT"


def main():
    # Extract arguments
    args = get_args()

    # Initialize logger (includes execution start logging)
    setup_logger(args.log_file)

    verify = args.verify_cert
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.info("TLS certificate verification: DISABLED (insecure)")
    else:
        logger.info("TLS certificate verification: ENABLED")

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

    upg_file = args.upg_file
    if upg_file:
        upg_file = os.path.abspath(upg_file)
    ppdm_release = args.ppdm_release
    pre_check, skip_upload = args.pre_check, args.skip_upload
    skip_snapshot, just_monitor = args.skip_snapshot, args.just_monitor

    # Constants
    api_endpoint = "/api/v2"
    api_port = 8443
    upg_port = 14443
    upg_timeout = 7200
    upg_token = "abcdefghijklmn"
    baremetal_check = "GENERIC"

    # Get the package name from the download URL if requested
    download_url = None
    if args.download_url and not just_monitor and not skip_upload:
        if upg_file:
            print(
                "---> Both --file and --url specified. "
                "Using local file, ignoring --url."
            )
            logger.info(
                "Both file and URL provided; using local file: %s", upg_file
            )
        else:
            download_user = args.download_user or os.environ.get(
                "PPDM_DOWNLOAD_USER"
            )
            download_password = args.download_password or os.environ.get(
                "PPDM_DOWNLOAD_PASSWORD"
            )
            if bool(download_user) != bool(download_password):
                print(
                    "Both download user and download password are required. "
                    "Exiting..."
                )
                logger.error("Only one of download user/password provided")
                raise SystemExit(1)

            download_url = args.download_url
            upg_file = download_url.split("/")[-1].split("?")[0]

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
        if upg_file or skip_upload or args.download_url:
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
        token = authenticate(ppdm_uri, username, password, verify=verify)

        if token:
            current_ver = check_deployment(ppdm_uri, token, verify=verify)
            print(f"---> PPDM is responsive, version: {current_ver}")
            if ppdm_release and current_ver == ppdm_release:
                print("-> PPDM already at target version")
                raise SystemExit(0)
            print("---> Proceeding to upgrade monitoring")
            logger.info("Proceeding to upgrade monitoring")

        upg_uri = f"https://{server}:{upg_port}"
        result = monitor_upg_activity(
            upg_uri, upg_token, upg_timeout, True, verify=verify
        )

        if result == True:
            print("-> PPDM upgraded successfully")
            logger.info("PPDM upgrade completed successfully")
            raise SystemExit(0)
        elif result == False:
            print("-> PPDM upgrade failed")
            print(f"---> Retry, rollback or export logs at {upg_uri}")
            logger.error("PPDM upgrade failed")
            raise SystemExit(1)
        else:
            print("-> PPDM upgrade timed out")
            logger.error("PPDM upgrade monitoring timed out")
            raise SystemExit(1)

    if not upg_file and not ppdm_release and not skip_upload:
        print(
            "Need to specify either upgrade file (--file), "
            "download URL (--url), or skip-upload. Exiting..."
        )
        logger.error(
            "Need to specify upgrade file, download URL, or skip-upload"
        )
        raise SystemExit(1)

    # Logs into the PPDM API
    ppdm_uri = f"https://{server}:{api_port}{api_endpoint}"
    logger.info("Authenticating to PPDM API: %s", server)
    token = authenticate(ppdm_uri, username, password, verify=verify)
    if not token:
        print("-> Login failed")
        raise SystemExit(1)

    # Getting PPDM configuration
    print("-> Obtaining PPDM configuration information")
    logger.info("Obtaining PPDM configuration")
    check_deployment_type(ppdm_uri, token, baremetal_check, verify=verify)
    current_ver = check_deployment(ppdm_uri, token, verify=verify)

    # Pre-upgrade checks
    print("-> Performing pre-upgrade version checks")
    logger.info("Performing pre-upgrade version checks")
    print("---> Current PPDM version:", current_ver)
    logger.info("Current PPDM version: %s", current_ver)

    version_checks = perform_version_checks(
        ppdm_uri, token, current_ver, ppdm_release, upg_file, verify=verify
    )

    # Upload or reuse upgrade package
    if skip_upload:
        upg_data = version_checks
        if not upg_data:
            print(
                f"No upgrade package for release {ppdm_release} was found "
                "on PPDM. Exiting..."
            )
            logger.error("No upgrade package found for %s", ppdm_release)
            raise SystemExit(1)
    else:
        if not version_checks:
            if download_url:
                print("-> Starting upgrade package download")
                upg_file = download_package(
                    download_url,
                    args.download_dir,
                    download_user,
                    download_password,
                    verify=verify
                )
                token = check_ppdm_availability(
                    ppdm_uri, username, password, verify=verify
                )

            print("-> Uploading PPDM upgrade package")
            upg_data = upload_package(ppdm_uri, token, upg_file, verify=verify)
            token = authenticate(ppdm_uri, username, password, verify=verify)
            if not token:
                print("-> Login failed after upload. Exiting...")
                raise SystemExit(1)
        else:
            print(
                "---> File upload skipped as a package of the same release "
                "already exists"
            )
            upg_data = version_checks

    upg_pkg_id = upg_data["id"]

    # Monitor pre-upgrade tasks
    monitor_preupg_activity(
        ppdm_uri, token, upg_pkg_id, upg_timeout, verify=verify
    )

    # Execute and monitor pre-check
    print("-> Performing pre-upgrade checks")
    perform_pre_check(ppdm_uri, token, upg_pkg_id, verify=verify)
    if not monitor_preupg_activity(
        ppdm_uri, token, upg_pkg_id, upg_timeout, verify=verify
    ):
        raise SystemExit(1)

    if pre_check:
        print("---> Pre-check parameter provided. Exiting")
        raise SystemExit(0)

    # Upgrade PPDM
    print("-> Upgrading PPDM to release", upg_data["packageVersion"])

    if skip_snapshot:
        upg_data["skipSnapshot"] = True

    if not check_hosting_vcenter(ppdm_uri, token, verify=verify):
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

    if upgrade_ppdm(ppdm_uri, token, upg_data, verify=verify):
        upg_uri = f"https://{server}:{upg_port}"
        result = monitor_upg_activity(
            upg_uri, upg_data["upgradeToken"], upg_timeout, verify=verify
        )
        if result == "TIMEOUT":
            print("-> Monitoring timed out, check the PPDM upgrade status")
            logger.error("PPDM upgrade monitoring timed out")
            raise SystemExit(1)
        if result == True:
            print("-> PPDM upgraded successfully")
        else:
            print("-> PPDM upgrade failed")
            print(f"---> Retry, roll back or export logs at {upg_uri}")
            logger.error("PPDM upgrade failed in main execution path")
            raise SystemExit(1)
    else:
        print("-> PPDM upgrade failed")
        logger.error("PPDM upgrade failed - result was False")
        raise SystemExit(1)

    # Post-upgrade validation
    print("-> Making sure PPDM is up and running")
    token = check_ppdm_availability(
        ppdm_uri, username, password, verify=verify
    )

    if token:
        print("---> PPDM is available")
        check_deployment(
            ppdm_uri, token, True, upg_data["packageVersion"], verify=verify
        )
        print("-> All tasks completed successfully")
    else:
        print("---> PPDM is not available yet, check again later...")


if __name__ == "__main__":
    main()
