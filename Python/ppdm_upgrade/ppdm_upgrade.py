#!/usr/bin/env python3

import argparse
import json
import sys
import time
import requests
import urllib3
import os

# The purpose of this script is to automate PowerProtect Data Manager lifecycle management
# Author - Idan Kentor <idan.kentor@dell.com>
# Version 1 - October 2023
# Copyright [2023] [Idan Kentor]

# Examples:
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -f /home/idan/dellemc-ppdm-upgrade-sw-19.14.0-27.pkg
# python ppdm_upgrade.py -s 10.0.0.1 -u idan -p "myTempPwd!"" -f c:\downloads\dellemc-ppdm-upgrade-sw-19.14.0-27.pkg -onlyprecheck
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -skipupload -release 19.14.0-27
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -f c:\downloads\dellemc-ppdm-upgrade-sw-19.14.0-27.pkg -skipsnapshot
# python ppdm_upgrade.py -s 10.0.0.1 -p "idanTempPwd!" -onlymonitor


urllib3.disable_warnings()

def get_args():
    # Gets command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to automate PowerProtect Data Manager lifecycle management')
    parser.add_argument('-s', '--server', required=True, dest='server',
                        action='store', help='PPDM server FQDN or IP')
    parser.add_argument('-u', '--username', required=False, dest='username',
                        action='store', default="admin", help='Optionally provide the PPDM username')
    parser.add_argument('-p', '--password', required=True, dest='password',
                        action='store', help='PPDM password')
    parser.add_argument('-f', '--file', required=False, dest='upgFile',
                        action='store', help='Full path to upgrade package')
    parser.add_argument('-onlyprecheck', '--only-pre-check', required=False, dest='preCheck',
                        action='store_true', help='Optionally stops after pre-check')
    parser.add_argument('-skipupload', '--skip-file-upload', required=False, dest='skipUpload',
                        action='store_true', help='Optionally skips file upload')
    parser.add_argument('-release', '--ppdm-release', required=False, dest='ppdmRelease',
                        action='store', help='Provide PPDM version if skipping package upload')
    parser.add_argument('-skipsnapshot', '--skip-snapshot', required=False, dest='skipSnapshot',
                        action='store_true', help='Optionally skips PPDM VM snapshot')
    parser.add_argument('-onlymonitor', '--only-monitor', required=False, dest='justMonitor',
                        action='store_true', help='Optionally only monitor running upgrade')    
    args = parser.parse_args()
    return args

def init_rest_call(callType, uri, token, payload=None, params=None, upload=None):
    # Generic function for REST calls
    monitor = False
    if uri.endswith("/login"):
        headers = {'Content-Type': 'application/json'}
    elif uri.endswith("/upgrade/status"):
         headers = {'Content-Type': 'application/json', 'Authorization': '{}'.format(token)}
         monitor = True
    elif upload:
        headers = {'Accept-Encoding': 'gzip, deflate, br', 'Authorization': 'Bearer {}'.format(token)}
    else:
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    if not upload:
        payload = json.dumps(payload)
    code = {200, 201, 202, 204}
    verify = False
    try:
        if callType.lower() == "get":
            response = requests.get(uri, headers=headers, params=params, verify=verify)
        elif callType.lower() == "post":
            if upload:
                response = requests.request("POST", uri, headers=headers, files=payload, verify=verify)
            else:
                response = requests.post(uri, headers=headers, params=params, data=payload, verify=verify)
        elif callType.lower() == "put":
            response = requests.put(uri, headers=headers, params=params, data=payload , verify=verify)
        elif callType.lower() == "patch":
            response = requests.patch(uri, headers=headers, params=params, data=payload , verify=verify)
        response.raise_for_status()
    except requests.exceptions.Timeout as err:
        print('-> Connection timed out:{} {}'.format(uri, err))
        return False
    except requests.exceptions.ConnectionError as err:
        if not monitor:
            print('-> Error Connecting to {}: {}'.format(uri, err))
        return False
    except requests.exceptions.RequestException as err:
        if response.status_code in (401, 502):
             return False
        print("-> The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code not in code):
        raise Exception('-> Failed to query {}, code: {}, body: {}'.format(uri, response.status_code, response.text))
    if not response.content:
        return True
    else:
        if uri.endswith("/login"):
            return response.json()["access_token"]
        try:
            return response.json()
        except BaseException:
            return response.content

def check_deployment(ppdmUri, token, postDeployment=None, targetVersion=None):
    # Validates that PPDM is ready for upgrade and healthy post-upgrade
    nodesUri = "{}/nodes".format(ppdmUri)
    nodes = init_rest_call("GET", nodesUri, token)
    ppdmNode = nodes["content"][0]
    if ppdmNode["status"] != "OPERATIONAL_RUNNING":
        if postDeployment:
            print("PPDM is on version {} but with state {}. Exiting...".format(ppdmNode["status"], ppdmNode[["version"]]))
            sys.exit(1)
        print("PPDM is not upgrade ready. Exiting...")
        sys.exit(1)
    else:
        if postDeployment:
            if not targetVersion:
                targetVersion = ppdmNode["version"]
            if ppdmNode["version"] == targetVersion:
                print("---> PPDM is operational on version {}".format(ppdmNode["version"]))
                return True
            else:
                print("Post-upgrade version checks failed. Exiting...")
                sys.exit(1)
        print("---> PPDM is upgrade ready")
        return ppdmNode["version"]

def perform_version_checks(ppdmUri, token, currentVersion, ppdmRelease, upgFile):
    # Performs pre-upgrade version and upgrade package validations
    if ppdmRelease:
        print("---> Checking upgrade to PPDM version:", ppdmRelease)
        if currentVersion == ppdmRelease:
            print("Current PPDM version is identical to the intended version. Exiting...")
            sys.exit(1)
        else:
            filter = 'packageVersion eq "{}" and category eq "ACTIVE"'.format(ppdmRelease)
    else:
        fileName = os.path.split(upgFile)[1]
        pkgVersion = os.path.splitext(fileName)[0].split("-sw-")[-1]
        print("---> Checking upgrade to PPDM version:", pkgVersion)
        if currentVersion == pkgVersion:
            print("Current PPDM version is identical to the intended version. Exiting...")
            sys.exit(1)
        else:
            filter = 'packageVersion eq "{}" and category eq "ACTIVE"'.format(pkgVersion)
    upgUri = "{}/upgrade-packages".format(ppdmUri)
    params = {"filter": filter}
    response = init_rest_call("GET", upgUri, token, None, params)
    try:
        return response["content"][0]
    except (IndexError, KeyError):
        filter = 'category eq "ACTIVE"'
        params = {"filter": filter}
        response = init_rest_call("GET", upgUri, token, None, params)
        if len(response["content"]) > 0:
            print("At least one upgrade package of a different version exists on PPDM - remove it and retry. Exiting...")
            sys.exit(1)
        return False
        
def check_hosting_vcenter(ppdmUri, token):
    # Checks if there is a vCenter configured as hosting
    assetSrcUri = "{}/inventory-sources".format(ppdmUri)
    filter = 'type eq "VCENTER" and details.vCenter.hosting eq true and details.vCenter.internal eq false'
    params = {"filter": filter}
    response = init_rest_call("GET", assetSrcUri, token, None, params)
    if len(response["content"]) == 1:
        return True
    else:
        return False

def upload_package(ppdmUri, token, upgFile):
    # Uploads upgrade package to PPDM
    try:
        with open(upgFile, 'rb') as fileHandle:
            upgUri = "{}/upgrade-packages".format(ppdmUri)
            fileName = os.path.split(upgFile)[1]
            payload = {"file": (fileName, fileHandle, 'application/octet-stream')}
            startTime = time.time()
            response = init_rest_call("POST", upgUri, token, payload, None, True)
            endTime = time.time()
    except IOError:
        print("Could not open upgrade package, exiting...")
        sys.exit(1)
    except MemoryError:
        print("Package upload failed due to insufuccient memory/disk space. Exiting...")
        sys.exit(1)
    if not response:
         print("Package upload failed, exiting...")
         sys.exit(1)
    if "id" not in response:
        print("Package upload failed, exiting...") 
        sys.exit(1)
    else:
        diffTime = round (endTime - startTime)
        print("---> Upload completed successfully in", diffTime // 60, "mins and", diffTime % 60, "secs")
    return response

def monitor_preupgrade_activity(ppdmUri, token, upgradeId, ppdmUpgradeTimeout):
    # Monitors pre-upgrade tasks
    monitorUri = "{}/upgrade-packages/{}".format(ppdmUri, upgradeId)
    interval = 5
    start = time.time()
    print("-> Monitoring upgrade ID {}".format(upgradeId))
    while True:
        if (time.time() - start) > ppdmUpgradeTimeout:
            break
        response = init_rest_call("GET", monitorUri, token)
        if response["state"] in ("AVAILABLE", "INSTALLED"):
            print('---> Monitoring state {}'.format(response['state']))
            return True
        if response["state"] == "PROCESSING":
            print('---> Monitoring state {}'.format(response['state']))
        elif response["state"] == "ERROR":
            print("\033[91m\033[1m->Action failed:\033[39m", json.dumps(response))
            break
        time.sleep(interval)
    return False

def authenticate(ppdmUri, username, password):
    # Login
    loginUri = "/login"
    ppdmUri += loginUri
    loginPayload = {"username": username, "password": password}
    token = init_rest_call("POST", ppdmUri, loginPayload, loginPayload)
    return token

def perform_precheck(ppdmUri, token, upgradeId):
    # Executes pre-upgrade checks
    preCheckUri = "{}/upgrade-packages/{}/precheck".format(ppdmUri, upgradeId)
    response = init_rest_call("POST", preCheckUri, token)
    return response

def upgrade_ppdm(ppdmUri, token, upgPkgData):
    # Upgrades PPDM
    upgUri = "{}/upgrade-packages/{}".format(ppdmUri, upgPkgData["id"])
    params = {"forceUpgrade": "true"}
    response = init_rest_call("PUT", upgUri, token, upgPkgData, params)
    if "category" in response:
        if response["category"] == "ACTIVE":
            return True
    return False

def check_ppdm_availability(server, token):
    # Checks if PPDM is available after a successfull upgrade
    ppdmCheckUri = "https://{}/isUp".format(server)
    for _ in range(3):
        response = init_rest_call("GET", ppdmCheckUri, token)
        if "success" in response:
            return True
        else:
            time.sleep(60)
    return False

def monitor_upgrade_activity(ppdmUri, upgradeToken, ppdmMonitorTimeout, postDeploy=None):
    # Continuously monitors PPDM upgrade operation
    monitorUri = "{}/upgrade/status".format(ppdmUri)
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
                sys.exit(1)
            if postDeploy:
                return "TIMEOUT"
        upgState = response[0]
        if upgState["upgradeStatus"] == "RUNNING":    
            print('---> Upgrade status: {} {}%'.format(upgState['upgradeStatus'], upgState["percentageCompleted"]))
            currentStg = upgState["currentStage"]
            print('----> Upgrade info: current component: {}, description: {} {}%'.format(currentStg["component"], currentStg["description"], currentStg["percentageCompleted"]))
            print('----> Upgrade info: seconds elapsed / remaining: {} / {}'.format(upgState['elapsedTime'], upgState["estimatedRemainingTime"]))
        elif upgState["upgradeStatus"] == "PENDING":
            print('---> Upgrade status: {}'.format(upgState['upgradeStatus']))
        elif upgState["upgradeStatus"] == "COMPLETED":
            print('---> Upgrade status: {} {}%'.format(upgState['upgradeStatus'], upgState["percentageCompleted"]))
            print('----> Upgrade completed in {} mins and {} seconds'.format(upgState['elapsedTime'] // 60, upgState['elapsedTime'] % 60))
            return True
        elif upgState["upgradeStatus"] == "FAILED":
            print('---> PPDM Upgrade FAILED')
            currentStg = upgState["currentStage"]
            print('----> Failed component: {}, description {}'.format(currentStg["component"], currentStg["description"]))
            return False
        time.sleep(interval)
    return False

def main():
    # Args assignment
    args = get_args()
    server, upgFile, preCheck, skipUpload = args.server, args.upgFile, args.preCheck, args.skipUpload
    username, password, skipSnapshot,  = args.username, args.password, args.skipSnapshot
    ppdmRelease, justMonitor = args.ppdmRelease, args.justMonitor
    
    # Const definition
    apiEndpoint = "/api/v2"
    ppdmApiPort = 8443
    ppdmUpgPort = 14443
    ppdmUpgradeTimeout = 3600
    upgradeToken = "abcdefghijklmn"

    # Arguments check
    if skipUpload and not ppdmRelease:
        print("The PPDM release must be provided when skipping package upload. Exiting...")
        sys.exit(1)    
    if ppdmRelease and not skipUpload:
        if upgFile:
            print("---> The 'ppdm-release' parameter is being ignored as it cannot be specified without 'skip-file-upload'")
            ppdmRelease = None
        else:
            print("Upgrade package and 'skip-upload' parameters were not specified. Exiting...")
            sys.exit(1)
    if not upgFile and not ppdmRelease and not skipUpload and not justMonitor:
        print("Need to specify either upgrade file or skip-upload or only-monitor. Exiting...")
        sys.exit(1)

    # Logs into the PPDM API
    ppdmUri = "https://{}:{}{}".format(server, ppdmApiPort, apiEndpoint)
    token = authenticate(ppdmUri, username, password)

    # Monitors running upgrade if only-monitor is specified
    if justMonitor:
        if upgFile or skipUpload or ppdmRelease:
            print("---> Ignoring parmaters because only-monitor is specified.")
        print("-> only-monitor parameter provided. Monitoring currently running upgrade.")
        ppdmUpgUri = "https://{}:{}".format(server, ppdmUpgPort)
        result = monitor_upgrade_activity(ppdmUpgUri, upgradeToken, ppdmUpgradeTimeout, True)
        if result == True:
            print("\033[92m\033[1m-> PPDM upgraded successfully\033[0m")
        elif result == False:
            print("\033[91m\033[1m-> PPDM upgrade failed\033[39m")
            sys.exit(1)
        else:
            next
        print("-> Making sure PPDM is up and running")
        if check_ppdm_availability(server, token):
            print("---> PPDM is available")
            check_deployment(ppdmUri, token, True)
            sys.exit(0)
        else:
            print("---> PPDM is not available yet, check again later...")
            sys.exit(1)

    # Getting PPDM configuration
    print("-> Obtaining PPDM configuration information")
    currentVersion = check_deployment(ppdmUri, token)
    
    # Performs pre-upgrade version and upgrade package checks
    print("-> Performing pre-upgrade version checks")
    print("---> Current PPDM version:", currentVersion)
    chkResult = perform_version_checks(ppdmUri, token, currentVersion, ppdmRelease, upgFile)
    if skipUpload:
        upgPkgData = chkResult
    else:
        if not chkResult:
            print("-> Uploading PPDM upgrade package")
            upgPkgData = upload_package(ppdmUri, token, upgFile)
            token = authenticate(ppdmUri, username, password)
        else:
            print("---> File upload skipped as a package of the same release already exists")
            upgPkgData = chkResult
    upgPkgId = upgPkgData["id"]
    
    # Monitors upgrade package processing activity 
    monitor_preupgrade_activity(ppdmUri, token, upgPkgId, ppdmUpgradeTimeout)
    
    # Executes and monitors pre-check
    print("-> Performing pre-upgrade checks")
    perform_precheck(ppdmUri, token, upgPkgId)
    monitor_preupgrade_activity(ppdmUri, token, upgPkgId, ppdmUpgradeTimeout)
    if preCheck:
        print("---> Pre-check parameter provided. Exiting")
        sys.exit(0)
    
    # Upgrading PPDM
    print("-> Upgrading PPDM to release", upgPkgData["packageVersion"])
    if skipSnapshot:
        upgPkgData["skipSnapshot"] = True
    if not check_hosting_vcenter(ppdmUri, token):
        print("---> PPDM VM snapshot is skipped because hosting vCenter is not configured")
        upgPkgData["skipSnapshot"] = True
    upgPkgData["state"] = "INSTALLED"
    upgPkgData["lockboxPassphrase"] = "1234567890abcdef"
    upgPkgData["upgradeToken"] = upgradeToken
    upgPkgData["certificateTrustedByUser"] = True
    if upgrade_ppdm(ppdmUri, token, upgPkgData):
        ppdmUpgUri = "https://{}:{}".format(server, ppdmUpgPort)
        result = monitor_upgrade_activity(ppdmUpgUri, upgPkgData["upgradeToken"], ppdmUpgradeTimeout)
        if result:
            print("\033[92m\033[1m-> PPDM upgraded successfully\033[0m")
        else:
            print("\033[91m\033[1m-> PPDM upgrade failed\033[39m")
            sys.exit(1)
    else:
            print("\033[91m\033[1m-> PPDM upgrade failed\033[39m")
            sys.exit(1)
    
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
