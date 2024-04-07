#!/usr/bin/env python3

import argparse
import json
import time
import os
import requests
import urllib3

# The purpose of this script is to automate PowerProtect Data Manager lifecycle management
# Author - Idan Kentor <idan.kentor@dell.com>
# Version 1 - October 2023
# Version 2 - March 2024
# Copyright [2024] [Idan Kentor]

# Examples:
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -f /home/idan/dellemc-ppdm-upgrade-sw-19.14.0-27.pkg
# python ppdm_upgrade.py -s 10.0.0.1 -u idan -p "myTempPwd!"" -f c:\downloads\dellemc-ppdm-upgrade-sw-19.15.0-25.pkg -onlyprecheck
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -skipupload -release 19.15.0-25
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -f c:\downloads\dellemc-ppdm-upgrade-sw-19.14.0-27.pkg -skipsnapshot
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
        dest="upgFile",
        action="store",
        help="Full path to upgrade package",
    )
    parser.add_argument(
        "-onlyprecheck",
        "--only-pre-check",
        required=False,
        dest="preCheck",
        action="store_true",
        help="Optionally stops after pre-check",
    )
    parser.add_argument(
        "-skipupload",
        "--skip-file-upload",
        required=False,
        dest="skipUpload",
        action="store_true",
        help="Optionally skips file upload",
    )
    parser.add_argument(
        "-release",
        "--ppdm-release",
        required=False,
        dest="ppdmRelease",
        action="store",
        help="Provide PPDM version if skipping package upload",
    )
    parser.add_argument(
        "-skipsnapshot",
        "--skip-snapshot",
        required=False,
        dest="skipSnapshot",
        action="store_true",
        help="Optionally skips PPDM VM snapshot",
    )
    parser.add_argument(
        "-onlymonitor",
        "--only-monitor",
        required=False,
        dest="justMonitor",
        action="store_true",
        help="Optionally only monitor running upgrade",
    )
    args = parser.parse_args()
    return args


def init_rest_call(verb, uri, token, payload=None, params=None, upload=None):
    """Generic function for REST calls"""
    monitor = False
    if uri.endswith("/login"):
        headers = {"Content-Type": "application/json"}
    elif uri.endswith("/upgrade/status"):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"{token}"
        }
        monitor = True
    elif upload:
        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Authorization": "Bearer " f"{token}",
        }
    else:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " f"{token}",
        }
    if not upload:
        payload = json.dumps(payload)
    code = {200, 201, 202, 204}
    verify = False
    timeout = 90
    try:
        if verb.lower() == "get":
            response = requests.get(
                uri,
                headers=headers,
                params=params,
                verify=verify,
                timeout=timeout
            )
        elif upload:
            response = requests.request(
                verb,
                uri,
                headers=headers,
                params=params,
                files=payload,
                verify=verify,
                timeout=None
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


def check_deployment(ppdmUri, token, postDeployment=None, targetVersion=None):
    """Validates that PPDM is ready for upgrade and healthy post-upgrade"""
    nodesUri = f"{ppdmUri}/nodes"
    nodes = init_rest_call("GET", nodesUri, token)
    ppdmNode = nodes["content"][0]
    if ppdmNode["status"] != "OPERATIONAL_RUNNING":
        if postDeployment:
            raise SystemExit(f"PPDM is on version {ppdmNode['version']} but with state {ppdmNode['status']}. Exiting...")
        raise SystemExit("PPDM is not upgrade ready. Exiting...")
    if postDeployment:
        if not targetVersion:
            targetVersion = ppdmNode["version"]
        if ppdmNode["version"] == targetVersion:
            print(f"---> PPDM is operational on version {ppdmNode['version']}")
            return True
        raise SystemExit("Post-upgrade version checks failed. Exiting...")
    print("---> PPDM is upgrade ready")
    return ppdmNode["version"]


def perform_version_checks(ppdmUri, token, currentVersion, ppdmRelease, upgFile):
    """Performs pre-upgrade version and upgrade package validations"""
    if ppdmRelease:
        print("---> Checking upgrade to PPDM version:", ppdmRelease)
        if currentVersion == ppdmRelease:
            raise SystemExit("Current PPDM version is identical to the intended version. Exiting...")
        query = f'packageVersion eq "{ppdmRelease}" and category eq "ACTIVE"'
    else:
        fileName = os.path.split(upgFile)[1]
        pkgVersion = os.path.splitext(fileName)[0].split("-sw-")[-1]
        print("---> Checking upgrade to PPDM version:", pkgVersion)
        if currentVersion == pkgVersion:
            raise SystemExit("Current PPDM version is identical to the intended version. Exiting...")
        query = f'packageVersion eq "{pkgVersion}" and category eq "ACTIVE"'
    upgUri = f"{ppdmUri}/upgrade-packages"
    params = {"filter": query}
    response = init_rest_call("GET", upgUri, token, None, params)
    try:
        return response["content"][0]
    except (IndexError, KeyError):
        query = 'category eq "ACTIVE"'
        params = {"filter": query}
        response = init_rest_call("GET", upgUri, token, None, params)
        if len(response["content"]) > 0:
            print(
                "At least one upgrade package of a different version already exists - remove it and retry. Exiting..."
            )
            raise SystemExit(1) from FileExistsError
        return False


def check_hosting_vcenter(ppdmUri, token):
    """Checks if there is a vCenter configured as hosting"""
    assetSrcUri = f"{ppdmUri}/inventory-sources"
    query = 'type eq "VCENTER" and details.vCenter.hosting eq true and details.vCenter.internal eq false'
    params = {"filter": query}
    response = init_rest_call("GET", assetSrcUri, token, None, params)
    return bool(len(response["content"]) == 1)


def upload_package(ppdmUri, token, upgFile):
    """Uploads upgrade package to PPDM"""
    try:
        with open(upgFile, "rb") as fileHandle:
            upgUri = f"{ppdmUri}/upgrade-packages"
            fileName = os.path.split(upgFile)[1]
            payload = {"file": (fileName, fileHandle, 'application/octet-stream')}
            startTime = time.time()
            response = init_rest_call("POST", upgUri, token, payload, None, True)
            endTime = time.time()
    except IOError as error:
        print("Could not open upgrade package, exiting...")
        raise SystemExit(1) from error
    except MemoryError as error:
        print("Package upload failed due to insufuccient memory/disk space. Exiting...")
        raise SystemExit(1) from error
    if not response:
        print("Package upload failed, exiting...")
        raise SystemExit(1)
    if "id" not in response:
        print("Package upload failed, exiting...")
        raise SystemExit(1)
    diffTime = round(endTime - startTime)
    print(
        "---> Upload completed successfully in",
        diffTime // 60,
        "mins and",
        diffTime % 60,
        "secs",
    )
    return response


def monitor_preupgrade_activity(ppdmUri, token, upgradeId, ppdmUpgradeTimeout):
    """Monitors pre-upgrade tasks"""
    monitorUri = f"{ppdmUri}/upgrade-packages/{upgradeId}"
    interval = 5
    start = time.time()
    print(f"-> Monitoring upgrade ID {upgradeId}")
    while True:
        if (time.time() - start) > ppdmUpgradeTimeout:
            break
        response = init_rest_call("GET", monitorUri, token)
        try:
            if response["state"] in ("AVAILABLE", "INSTALLED"):
                print(f"---> Monitoring state {response['state']}")
                return True
            if response["state"] == "PROCESSING":
                print(f"---> Monitoring state {response['state']}")
            elif response["state"] in ("ERROR", "PRECHECK_FAILED"):
                print("\033[91m\033[1m->Pre-check failed:\033[39m")
                print(json.dumps(response, indent=4))
                return False
        except TypeError:
            pass
        time.sleep(interval)
    return False


def authenticate(ppdmUri, username, password):
    """Login"""
    loginUri = "/login"
    ppdmUri += loginUri
    loginPayload = {"username": username, "password": password}
    token = init_rest_call("POST", ppdmUri, loginPayload, loginPayload)
    return token


def perform_precheck(ppdmUri, token, upgradeId):
    """Executes pre-upgrade checks"""
    preCheckUri = f"{ppdmUri}/upgrade-packages/{upgradeId}/precheck"
    response = init_rest_call("POST", preCheckUri, token)
    return response


def upgrade_ppdm(ppdmUri, token, upgPkgData):
    """Upgrades PPDM"""
    upgUri = f"{ppdmUri}/upgrade-packages/{upgPkgData['id']}"
    params = {"forceUpgrade": "true"}
    upgPkgData["sizeInBytes"] = int(float(upgPkgData["sizeInBytes"]))
    response = init_rest_call("PUT", upgUri, token, upgPkgData, params)
    if "category" in response:
        if response["category"] == "ACTIVE":
            return True
    return False


def check_ppdm_availability(server, token):
    """Checks if PPDM is available after a successfull upgrade"""
    ppdmCheckUri = f"https://{server}/isUp"
    for _ in range(3):
        response = init_rest_call("GET", ppdmCheckUri, token)
        if "success" in response:
            return True
        time.sleep(60)
    return False


def monitor_upgrade_activity(
    ppdmUri, upgradeToken, ppdmMonitorTimeout, postDeploy=None
):
    """Continuously monitors PPDM upgrade operations"""
    monitorUri = f"{ppdmUri}/upgrade/status"
    interval = 10
    componentTimeout = 600
    componentInterval = 30
    start = time.time()
    print("---> Monitoring PPDM upgrade")
    while True:
        if (time.time() - start) > ppdmMonitorTimeout:
            break
        try:
            response = init_rest_call("GET", monitorUri, upgradeToken)
        except BaseException:
            time.sleep(componentInterval)
            response = init_rest_call("GET", monitorUri, upgradeToken)
        componentstart = time.time()
        while not response:
            print("---> Polling timed out, retrying...")
            time.sleep(componentInterval)
            response = init_rest_call("GET", monitorUri, upgradeToken)
            if (time.time() - componentstart) > componentTimeout:
                print("Timed out waiting for upgrade to complete. Exiting...")
                raise SystemExit(1)
            if postDeploy:
                return "TIMEOUT"
        upgState = response[0]
        if upgState["upgradeStatus"] == "RUNNING":
            print(
                f"---> Upgrade status: {upgState['upgradeStatus']} {upgState['percentageCompleted']}%"
            )
            currentStg = upgState["currentStage"]
            print(
                f"----> Upgrade info: current component: {currentStg['component']}, description: {currentStg['description']} {currentStg['percentageCompleted']}%"
            )
            print(
                f"----> Upgrade info: seconds elapsed / remaining: {upgState['elapsedTime']} / {upgState['estimatedRemainingTime']}"
            )
        elif upgState["upgradeStatus"] == "PENDING":
            print(f"---> Upgrade status: {upgState['upgradeStatus']}")
        elif upgState["upgradeStatus"] == "COMPLETED":
            print(
                f"---> Upgrade status: {upgState['upgradeStatus']} {upgState['percentageCompleted']}%"
            )
            print(
                f"----> Upgrade completed in {upgState['elapsedTime'] // 60} mins and {upgState['elapsedTime'] % 60} seconds"
            )
            return True
        elif upgState["upgradeStatus"] == "FAILED":
            print("---> PPDM Upgrade FAILED")
            currentStg = upgState["currentStage"]
            print(
                f"----> Failed component: {currentStg['component']}, description {currentStg['description']}"
            )
            return False
        time.sleep(interval)
    return False


def main():
    # Args assignment
    args = get_args()
    server, upgFile = args.server, args.upgFile
    preCheck, skipUpload = args.preCheck, args.skipUpload
    username, password = args.username, args.password
    skipSnapshot, ppdmRelease = args.skipSnapshot, args.ppdmRelease
    justMonitor = args.justMonitor

    # Const definition
    apiEndpoint = "/api/v2"
    ppdmApiPort = 8443
    ppdmUpgPort = 14443
    ppdmUpgradeTimeout = 3600
    upgradeToken = "abcdefghijklmn"

    # Arguments check
    if skipUpload and not ppdmRelease:
        print(
            "The PPDM release must be provided when skipping package upload. Exiting..."
        )
        raise SystemExit(1)
    if ppdmRelease and not skipUpload:
        if upgFile:
            print(
                "---> Ignoring 'ppdm-release' parameter as it requires'skip-file-upload'"
            )
            ppdmRelease = None
        else:
            print(
                "Upgrade package and 'skip-upload' parameters were not specified. Exiting..."
            )
            raise SystemExit(1)
    if not upgFile and not ppdmRelease and not skipUpload and not justMonitor:
        print(
            "Need to specify either upgrade file or skip-upload or only-monitor. Exiting..."
        )
        raise SystemExit(1)

    # Logs into the PPDM API
    ppdmUri = f"https://{server}:{ppdmApiPort}{apiEndpoint}"
    token = authenticate(ppdmUri, username, password)

    # Monitors running upgrade if only-monitor is specified
    if justMonitor:
        if upgFile or skipUpload or ppdmRelease:
            print("---> Ignoring parmaters because only-monitor is specified.")
        print(
            "-> only-monitor parameter provided. Monitoring currently running upgrade."
        )
        ppdmUpgUri = "https://{server}:{ppdmUpgPort}"
        result = monitor_upgrade_activity(
            ppdmUpgUri, upgradeToken, ppdmUpgradeTimeout, True
        )
        if result is True:
            print("\033[92m\033[1m-> PPDM upgraded successfully\033[0m")
        elif result is False:
            print("\033[91m\033[1m-> PPDM upgrade failed\033[39m")
            raise SystemExit(1)
        else:
            pass
        print("-> Making sure PPDM is up and running")
        if check_ppdm_availability(server, token):
            print("---> PPDM is available")
            check_deployment(ppdmUri, token, True)
            raise SystemExit(0)
        raise SystemExit("---> PPDM is not available yet, check again later...")

    # Getting PPDM configuration
    print("-> Obtaining PPDM configuration information")
    currentVersion = check_deployment(ppdmUri, token)

    # Performs pre-upgrade version and upgrade package checks
    print("-> Performing pre-upgrade version checks")
    print("---> Current PPDM version:", currentVersion)
    chkResult = perform_version_checks(
        ppdmUri, token, currentVersion, ppdmRelease, upgFile
    )
    if skipUpload:
        upgPkgData = chkResult
    else:
        if not chkResult:
            print("-> Uploading PPDM upgrade package")
            upgPkgData = upload_package(ppdmUri, token, upgFile)
            token = authenticate(ppdmUri, username, password)
        else:
            print(
                "---> File upload skipped as a package of the same release already exists"
            )
            upgPkgData = chkResult
    upgPkgId = upgPkgData["id"]

    # Monitors upgrade package processing activity
    monitor_preupgrade_activity(ppdmUri, token, upgPkgId, ppdmUpgradeTimeout)

    # Executes and monitors pre-check
    print("-> Performing pre-upgrade checks")
    perform_precheck(ppdmUri, token, upgPkgId)
    monitor = monitor_preupgrade_activity(ppdmUri, token, upgPkgId, ppdmUpgradeTimeout)
    if not monitor:
        raise SystemExit(1)
    if preCheck:
        print("---> Pre-check parameter provided. Exiting")
        raise SystemExit(0)

    # Upgrading PPDM
    print("-> Upgrading PPDM to release", upgPkgData["packageVersion"])
    if skipSnapshot:
        upgPkgData["skipSnapshot"] = True
    if not check_hosting_vcenter(ppdmUri, token):
        print(
            "---> Skipping PPDM VM snapshot because hosting vCenter is not configured"
        )
        upgPkgData["skipSnapshot"] = True
    upgPkgData["state"] = "INSTALLED"
    upgPkgData["lockboxPassphrase"] = "1234567890abcdef"
    upgPkgData["upgradeToken"] = upgradeToken
    upgPkgData["certificateTrustedByUser"] = True
    upgPkgData["eula"] = {"productEulaAccepted": True}
    if upgrade_ppdm(ppdmUri, token, upgPkgData):
        ppdmUpgUri = f"https://{server}:{ppdmUpgPort}"
        result = monitor_upgrade_activity(
            ppdmUpgUri, upgPkgData["upgradeToken"], ppdmUpgradeTimeout
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
    if check_ppdm_availability(server, token):
        print("---> PPDM is available")
        token = authenticate(ppdmUri, username, password)
        check_deployment(ppdmUri, token, True, upgPkgData["packageVersion"])
        print("-> All tasks completed successfully")
    else:
        print("---> PPDM is not available yet, check again later...")


if __name__ == "__main__":
    main()
