#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
import time
import requests
import urllib3

# This script purpose is to automate PowerProtect Data Manager deployment
# Author - Idan Kentor <idan.kentor@dell.com>
# Version 4 - June 2024
# Copyright [2024] [Idan Kentor]

# Examples:
# python ppdm_deploy.py -configfile ppdm-config-minimal.json
# python ppdm_deploy.py -configfile ppdm-prod-config.json -vc -dd
# python ppdm_deploy.py -configfile ppdm-prod-config.json -vc -dd -ppdm
# python ppdm_deploy.py -configfile ppdm-prod-config.json -vc -dd -ppdm -cross
# python ppdm_deploy.py -configfile ppdm-prod-config.json -skipova
# python ppdm_deploy.py -configfile ppdm_test.json -justova


urllib3.disable_warnings()


def get_args():
    """Gets command line args from the user"""
    parser = argparse.ArgumentParser(
        description="Script to automate PowerProtect Data Manager deployment"
    )
    parser.add_argument(
        "-configfile",
        "--config-file",
        required=True,
        dest="configfile",
        action="store",
        help="Full path to the JSON config file",
    )
    parser.add_argument(
        "-skipova",
        "--skip-ova",
        required=False,
        dest="skipova",
        action="store_true",
        help="Optionally skips OVA deployment",
    )
    parser.add_argument(
        "-justova",
        "--just-ova",
        required=False,
        dest="justova",
        action="store_true",
        help="Optionally stops after OVA deployment",
    )
    parser.add_argument(
        "-vc",
        "--register-vcenter",
        required=False,
        dest="regVC",
        action="store_true",
        help="Optionally registers vCenter in PPDM",
    )
    parser.add_argument(
        "-novcplugin",
        "--prevent-plugin-install",
        required=False,
        dest="noVcPlugin",
        action="store_false",
        help="Prevents vCenter plugin deployment",
    )
    parser.add_argument(
        "-dd",
        "--add-dd",
        required=False,
        dest="addDD",
        action="store_true",
        help="Optionally adds PowerProtect DD to PPDM",
    )
    parser.add_argument(
        "-ppdm",
        "--connect-ppdm",
        required=False,
        dest="connectPeerPPDM",
        action="store_true",
        help="Optionally connects remote PPDM system",
    )
    parser.add_argument(
        "-cross",
        "--bi-directional",
        required=("--ppdm" in sys.argv),
        dest="crossConnect",
        action="store_true",
        help="Optionally configures bi-directional \
                            communication between the two PPDM systems",
    )
    args = parser.parse_args()
    return args


def read_config(configfile):
    """Reads config file, validates params and assigns to the config dict"""
    with open(configfile, "r", encoding="utf-8") as fileHandle:
        try:
            config = json.load(fileHandle)
        except json.decoder.JSONDecodeError as error:
            print("\033[91m\033[1m->Cannot parse JSON config file:\033[0m", {error})
            raise SystemExit(1) from error
    fileHandle.close()
    for key in list(config.keys()):
        if key.startswith("_comment"):
            config.pop(key)
    config["ppdmIpV6"] = config.get("ppdmIpV6", False)
    if config["ppdmIpV6"]:
        if not config.get("ppdmIpV6Netmask") or not config.get("ppdmIpV6Gateway"):
            print("\033[91m\033[1m->Missing IPv6 configuration parameters\033[0m")
            raise SystemExit(1)
    if not config["ppdmIpV6"]:
        config["ppdmIpV4"] = config.get("ppdmIpV4", False)
        if not config["ppdmIpV4"]:
            print("\033[91m\033[1m->Missing PPDM IPv4 address\033[0m")
            raise SystemExit(1)
        config["ppdmIpV4Netmask"] = config.get("ppdmIpV4Netmask", False)
        config["ppdmIpv4Gateway"] = config.get("ppdmIpv4Gateway", False)
        if not config["ppdmIpV4Netmask"] or not config["ppdmIpv4Gateway"]:
            print("\033[91m\033[1m->Missing IPv4 configuration parameters\033[0m")
            raise SystemExit(1)
    if not config.get("ppdmDatastore"):
        print("\033[91m\033[1m->No Datastore provided, specify DS for PPDM\033[0m")
        raise SystemExit(1)
    if not config.get("ppdmMgmtNetwork"):
        print("\033[91m\033[1m->Management Network Port Group must be specified")
        raise SystemExit(1)
    if not config.get("ntpServers") or not config.get("dnsServers"):
        print("\033[91m\033[1m->Missing DNS or NTP IP addresses\033[0m")
        raise SystemExit(1)
    config["ntpServers"] = config["ntpServers"][0].split(", ")
    config["dnsServers"] = config["dnsServers"][0].split(", ")
    config["licenseFile"] = config.get("licenseFile", "trial")
    for encryptType in ("protectionEncryption", "replicationEncryption"):
        config[encryptType] = config.get(encryptType, True)
    if not isinstance(config[encryptType], bool):
        print(f"\033[91m\033[1m-> invalid value for {encryptType}\033[0m")
        raise SystemExit(1)
    for assetType in ["vc", "dd", "peerPpdm"]:
        if all(
            key in config
            for key in (
                assetType + "FQDNorIP",
                assetType + "User",
                assetType + "Password",
            )
        ):
            config[assetType + "Valid"] = True
            if config[assetType + "FQDNorIP"][0].isdigit():
                config[assetType + "NiceName"] = (
                    assetType.upper() + config[assetType + "FQDNorIP"].split(".")[3]
                )
            else:
                config[assetType + "NiceName"] = config[assetType + "FQDNorIP"].split(".")[0]
        else:
            config[assetType + "Valid"] = False
    if all(key in config for key in ("smtpMailServer", "smtpMailFrom", "smtpPort")):
        config["smtp"] = True
    else:
        config["smtp"] = False
    if config.get("smtpUser") and config.get("smtpPassword"):
        config["smtpAuth"] = True
    else:
        config["smtpAuth"] = False
    if not config.get("autoSupport"):
        if config["smtp"]:
            config["autoSupport"] = True
        else:
            config["autoSupport"] = False
    return config


def create_ovftool_command(config):
    """Forms the required ovftool command"""
    print()
    ppdmOvfExec = f'{config["ovfToolLocation"]} --noDestinationSSLVerify --skipManifestCheck --acceptAllEulas --powerOn --name="{config["ppdmVmName"]}" '
    ppdmOvfExec += f'--diskMode=thin --datastore={config["ppdmDatastore"]} --net:"VM Network"="{config["ppdmMgmtNetwork"]}" '
    if not config["ppdmIpV6"]:
        ppdmOvfExec += f'--prop:vami.ip0.brs={config["ppdmIpV4"]} --prop:vami.netmask0.brs="{config["ppdmIpV4Netmask"]}" --prop:vami.gateway.brs="{config["ppdmIpv4Gateway"]}" '
    else:
        ppdmOvfExec += f'--prop:vami.ip0.brs={config["ppdmIpV6"]} --prop:vami.netmask0.brs="{config["ppdmIpV6Netmask"]}" --prop:vami.gateway.brs="{config["ppdmIpV6Gateway"]}" '
    ppdmOvfExec += f'--prop:vami.DNS.brs="{", ".join(config["dnsServers"])}" --prop:vami.fqdn.brs="{config["ppdmFQDN"]}" '
    ppdmOvfExec += f'--deploymentOption="{config["platform"]}" "{config["ppdmOVALocation"]}" '
    ppdmOvfExec += f'vi://"{config["vcUser"]}":"{config["vcPassword"]}"@{config["vcFQDNorIP"]}/{config["datacenter"]}/host/{config["esxCluster"]}/'
    return ppdmOvfExec


def exec_ova_provisioning(ovfexec):
    """Executes ovftool commands"""
    exitCode = os.system(ovfexec)
    if exitCode == 0:
        print("\033[92m\033[1m---> OVA deployment completed successfully\033[0m")
    else:
        print("\033[91m\033[1m---> OVA deployment failed\033[0m")
        raise SystemExit(1)


def check_connectivity(ipAddress, ppdmApiTimeout):
    """Generic call to check connectivity to a given IP address"""
    interval = 5
    start = time.time()
    if platform.system().lower() == "windows":
        pingCmd = f"ping {ipAddress} -n 3"
    else:
        pingCmd = f"ping {ipAddress} -c 3"
    while True:
        if (time.time() - start) > ppdmApiTimeout:
            return False
        result = subprocess.run(
            pingCmd, shell=True, stdout=subprocess.PIPE, check=False
        )
        if result.returncode == 0:
            return True
        time.sleep(interval)


def check_api_accessibility(ppdmIp, ppdmApiTimeout):
    """Continuously checks if PPDM API is available"""
    apiEndpoint = f"https://{ppdmIp}/eula.html"
    interval = 30
    start = time.time()
    while True:
        if (time.time() - start) > ppdmApiTimeout:
            print("PPDM API check timed out. Exiting")
            raise SystemExit(1)
        if init_rest_call("GET", apiEndpoint, None, None, None, True):
            return True
        print("---> PPDM API is unreachable. Retrying")
        time.sleep(interval)


def init_rest_call(callType, uri, token, payload=None, params=None, deploy=None):
    """Generic function for REST calls"""
    if uri.endswith("/login") or deploy:
        headers = {"Content-Type": "application/json"}
    else:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " f"{token}",
        }
    payload = json.dumps(payload)
    code = {200, 201, 202, 204}
    verify = False
    timeout = 90
    try:
        if callType.lower() == "get":
            response = requests.get(
                uri,
                headers=headers,
                params=params,
                verify=verify,
                timeout=timeout
            )
        else:
            response = requests.request(
                callType,
                uri,
                headers=headers,
                params=params,
                data=payload,
                verify=verify,
                timeout=timeout,
            )
        response.raise_for_status()
    except requests.exceptions.ConnectionError as error:
        # Probes for API accessibility
        if deploy:
            return False
        print(f"\033[91m\033[1m->Error Connecting to {uri}: {error}\033[39m")
        raise SystemExit(1) from error
    except requests.exceptions.Timeout as error:
        print(f"\033[91m\033[1m->Connection timed out {urllib3}: {error}\033[39m")
        raise SystemExit(1) from error
    except requests.exceptions.RequestException as error:
        if deploy and response.status_code in (401, 502):
            return False
        print(
            f"\033[91m\033[1m->The call {response.request.method} {response.url} failed with exception:{error}\033[39m"
        )
    if response.status_code not in code:
        raise Exception(
            f"\033[91m\033[1m->Failed to query {uri}, code: {response.status_code}, body: {response.text}\033[39m"
        )
    if not response.content:
        return True
    else:
        if uri.endswith("/login"):
            return response.json()["access_token"]
        try:
            return response.json()
        except BaseException:
            return response.content


def check_deployment(ppdmUri, token):
    """Validates that PPDM is ready for deployment"""
    nodesUriSuffix = "/nodes"
    ppdmUri += nodesUriSuffix
    nodes = init_rest_call("GET", ppdmUri, token)
    if nodes["content"][0]["status"] != "PENDING":
        print("PPDM is not available for deployment. Exiting...")
        raise SystemExit(1)
    print("---> PPDM is deployment ready")
    return nodes["content"][0]["id"]


def get_deploy_config(ppdmUri, token, nodeId):
    """Gets PPDM deployment configuration"""
    configUriSuffix = "/configurations"
    ppdmUri += configUriSuffix
    deployConfig = init_rest_call("GET", ppdmUri, token)
    for deployConfigItem in deployConfig["content"]:
        if deployConfigItem["nodeId"] == nodeId:
            desiredDeployConfig = deployConfigItem
    if not desiredDeployConfig:
        print("Could not detect a valid configuration. Exiting")
        raise SystemExit(1)
    return desiredDeployConfig


def accept_eula(eulaType, ppdmUri, token):
    """Accepts PPDM EULAs by type"""
    eulaUriSuffix = f"/eulas/{eulaType}"
    ppdmUri += eulaUriSuffix
    payload = {"accepted": True}
    response = init_rest_call("PATCH", ppdmUri, token, payload)
    if not response["accepted"]:
        print(f"{eulaType} EULA could not be accepted, exiting...")
        raise SystemExit(1)
    print(f"---> {eulaType} EULA accepted")
    return True


def apply_license(licenseFile, ppdmUri, token):
    """Applies PPDM license from file"""
    if licenseFile != "trial":
        try:
            fileHandle = open(licenseFile, "r", encoding="utf-8")
            licenseContent = fileHandle.read()
            fileHandle.close()
        except (OSError, FileNotFoundError):
            licenseFile = "trial"
    else:
        print("-> Using Trial license")
        return True
    licenseUriSuffix = "/licenses"
    ppdmUri += licenseUriSuffix
    payload = {"type": "CAPACITY", "key": licenseContent}
    response = init_rest_call("POST", ppdmUri, token, payload)
    if response.get("status") == "VALID":
        print("-> Using Capacity license")
        return True
    print("-> Using Trial license")
    return False


def config_smtp(config, ppdmUri, token):
    """Applying SMTP settings"""
    smtpSuffix = "/smtp"
    ppdmUri += smtpSuffix
    payload = {
        "mailServer": config["smtpMailServer"],
        "mailFrom": config["smtpMailFrom"],
        "port": config["smtpPort"],
    }
    if config["smtpAuth"]:
        payload["username"] = config["smtpUser"]
        payload["password"] = config["smtpPassword"]
    response = init_rest_call("POST", ppdmUri, token, payload)
    if "id" in response:
        return True
    print("Could not apply SMTP settings. Exiting")
    return False


def apply_encryption_settings(config, ppdmUri, token):
    """Applying Encryption settings"""
    encrSetUriSuffix = "/common-settings/ENCRYPTION_SETTING"
    ppdmUri += encrSetUriSuffix
    encrSetPayload = {"id": "ENCRYPTION_SETTING"}
    protectionEncryption = {
        "name": "enableProtectionEncryption",
        "value": str(config["protectionEncryption"]).lower(),
        "type": "BOOLEAN",
    }
    replicationEncryption = {
        "name": "enableReplicationEncryption",
        "value": str(config["replicationEncryption"]).lower(),
        "type": "BOOLEAN",
    }
    encrSetPayload["properties"] = []
    encrSetPayload["properties"] = protectionEncryption, replicationEncryption
    response = init_rest_call("PUT", ppdmUri, token, encrSetPayload)
    try:
        if response["id"] != encrSetPayload["id"]:
            print("Could not apply encryption settings. Exiting")
            raise SystemExit(1)
        for responseEncrSettings in response["properties"]:
            if responseEncrSettings["name"] == "enableProtectionEncryption":
                if config["replicationEncryption"] != bool(
                    responseEncrSettings["value"]
                ):
                    print("Could not apply encryption settings. Exiting")
                    raise SystemExit(1)
            elif responseEncrSettings["name"] == "enableReplicationEncryption":
                if config["protectionEncryption"] != bool(
                    responseEncrSettings["value"]
                ):
                    print("Could not apply encryption settings. Exiting")
                    raise SystemExit(1)
    except KeyError:
        print("Could not apply encryption settings. Exiting")
        raise SystemExit(1) from KeyError
    return True


def get_time_zone(config, ppdmUri, token):
    """Determines the time zone"""
    if "timeZone" not in config:
        config["timeZone"] = str(datetime.datetime.now().astimezone().tzinfo).split(" ", maxsplit=1)[0]
    if config["timeZone"].lower() == "eastern" or config["timeZone"].lower() == "et":
        config["timeZone"] = "EST"
    elif config["timeZone"].lower() == "central" or config["timeZone"].lower() == "ct":
        config["timeZone"] = "CST6CDT"
    elif config["timeZone"].lower() == "pacific" or config["timeZone"].lower() == "pt":
        config["timeZone"] = "PST8PDT"
    elif config["timeZone"].lower() == "etc" or config["timeZone"].lower() == "utc":
        config["timeZone"] = "Etc/UTC"
    ppdmUri += "/timezones"
    timeZoneList = init_rest_call("GET", ppdmUri, token)
    for tz in timeZoneList["content"]:
        if config["timeZone"] in tz["name"]:
            config["timeZone"] = tz["id"]
    print(f"-> Time zone detected: {config['timeZone']}")
    return config


def build_deployment_config(config, deployConfig):
    """Forms the PPDM deployment config"""
    deployConfig["timeZone"] = config["timeZone"]
    for network in deployConfig["networks"]:
        if "nslookupSuccess" in network:
            if network["nslookupSuccess"]:
                print("-> Name resolution completed successfully")
            else:
                print("-> Warning: name resolution issues")
            break
    deployConfig["ntpServers"] = config["ntpServers"]
    for user in deployConfig["osUsers"]:
        user["password"] = config[user["userName"] + "DefaultPwd"]
        user["newPassword"] = config["ppdmAdminPwd"]
    deployConfig["applicationUserPassword"] = config["ppdmAdminPwd"]
    if config["autoSupport"]:
        deployConfig["autoSupport"] = True
    deployConfig["gettingStartedCompleted"] = True
    return deployConfig


def bootstrap_ppdm_deployment(ppdmUri, token, deployConfig):
    """Initiates the PPDM deployment"""
    deployUri = f"/configurations/{deployConfig['id']}"
    ppdmUri += deployUri
    deployResp = init_rest_call("PUT", ppdmUri, token, deployConfig)
    if "nodeId" in deployResp:
        return True
    return False


def monitor_deploy_activity(
    ppdmUri, token, deployConfigId, ppdmDeployTimeout, adminPwd
):
    """Monitors deployment operation"""
    monitorUri = f"{ppdmUri}/configurations/{deployConfigId}/config-status"
    interval = 5
    retryInterval = 30
    start = time.time()
    requiresAuth = False
    username = "admin"
    print(f"---> Deploying configuration {deployConfigId}")
    while True:
        if (time.time() - start) > ppdmDeployTimeout:
            break
        response = init_rest_call("GET", monitorUri, token)
        if not response:
            if not requiresAuth:
                response = init_rest_call("GET", monitorUri, token, None, None, True)
            else:
                token = authenticate(ppdmUri, username, adminPwd)
                try:
                    response = init_rest_call(
                        "GET", monitorUri, token, None, None, True
                    )
                except:
                    time.sleep(retryInterval)
                    response = init_rest_call(
                        "GET", monitorUri, token, None, None, True
                    )
                requiresAuth = True
        if response["status"] == "SUCCESS":
            print(f"---> Deployment status {response['status']} {response['percentageCompleted']}%")
            return True
        if response["status"] == "ERROR":
            print("\033[91m\033[1m->Action failed:\033[39m", json.dumps(response))
            break
        print(f"---> Deployment status {response['status']} {response['percentageCompleted']}%")
        time.sleep(interval)
    return False


def authenticate(ppdmUri, username, password):
    """Login"""
    loginUri = "/login"
    ppdmUri += loginUri
    loginPayload = {"username": username, "password": password}
    token = init_rest_call("POST", ppdmUri, loginPayload, loginPayload)
    return token


def accept_certificate(assetType, config, ppdmUri, token):
    """Accepts host certificate"""
    certsUri = "/certificates"
    ppdmUri += certsUri
    params = {
        "host": config[assetType + "FQDNorIP"],
        "port": config[assetType + "Port"],
        "type": "HOST",
    }
    cert = init_rest_call("GET", ppdmUri, token, None, params)
    if "id" in cert[0]:
        cert[0]["state"] = "ACCEPTED"
        ppdmUri += f"/{cert[0]['id']}"
        cert = init_rest_call("PUT", ppdmUri, token, cert[0])
        return True
    print(f"Cannot add {assetType.upper()}. Could not accept certificate")
    return False


def add_credentials(assetType, config, ppdmUri, token):
    """Adds credentials for a given asset source type"""
    credsSuffix = "/credentials"
    ppdmUri += credsSuffix
    if assetType == "VCENTER":
        assetTypeAlt = "vc"
    elif assetType == "DATADOMAIN":
        assetTypeAlt = "dd"
    elif assetType == "POWERPROTECT":
        assetTypeAlt = "peerPpdm"
    payload = {
        "type": assetType,
        "name": config[assetTypeAlt + "NiceName"],
        "username": config[assetTypeAlt + "User"],
        "password": config[assetTypeAlt + "Password"],
    }
    response = init_rest_call("POST", ppdmUri, token, payload)
    if "id" in response:
        return response["id"]
    return False


def config_auto_support(ppdmUri, token):
    """Configures AutoSupport"""
    supportUri = "/common-settings/TELEMETRY_SETTING"
    ppdmUri += supportUri
    response = init_rest_call("GET", ppdmUri, token)
    if "id" in response:
        for element in response["properties"]:
            if element["name"] == "transportType":
                element["value"] = "EMAIL"
    del response["_links"]
    payload = response
    response = init_rest_call("PUT", ppdmUri, token, payload)
    if "id" in response:
        print("-> AutoSupport configured successfully")
        return True
    print("-> AutoSupport could not be configured")
    return False


def register_asset_source(assetType, config, ppdmUri, token):
    """Registers asset source"""
    if assetType == "VCENTER":
        assetTypeAlt = "vc"
        assetTypeAlt2 = "vCenter"
    elif assetType == "DATADOMAIN":
        assetTypeAlt = "dd"
        assetTypeAlt2 = "PowerProtect DD"
    credsId = add_credentials(assetType, config, ppdmUri, token)
    if not credsId:
        print(f"Could not add {assetTypeAlt2} credentials")
        return False
    invSrcSuffix = "/inventory-sources"
    ppdmUri += invSrcSuffix
    payload = {
        "type": assetType,
        "name": config[assetTypeAlt + "NiceName"],
        "address": config[assetTypeAlt + "FQDNorIP"],
        "port": config[assetTypeAlt + "Port"],
        "credentials": {"id": credsId},
    }
    if assetType == "DATADOMAIN":
        payload["type"] = "EXTERNALDATADOMAIN"
    elif assetType == "VCENTER":
        vcDetails = {
            "hosting": True,
            "vSphereUiIntegration": config["noVcPlugin"]
        }
        payload["details"] = {"vCenter": vcDetails}
    response = init_rest_call("POST", ppdmUri, token, payload)
    if "id" in response:
        print(f"-> {assetTypeAlt2} registered successfully")
        if "vCenter" in response["details"]:
            if response["details"]["vCenter"]["hosting"]:
                print("--> Hosting vCenter configured successfully")
            if not config["noVcPlugin"]:
                if not response["details"]["vCenter"]["vSphereUiIntegration"]:
                    print("--> PPDM vCenter plugin installation was skipped")
        return True
    print(f"-> {assetTypeAlt2} could not be registered")
    return False


def monitor_activity(ppdmUri, token, activityId, ppdmMonitorTimeout):
    """continuously monitors activity by ID"""
    monitorUri = f"{ppdmUri}/activities/{activityId}"
    interval = 5
    start = time.time()
    print(f"---> Monitoring activity ID {activityId}")
    while True:
        if (time.time() - start) > ppdmMonitorTimeout:
            break
        response = init_rest_call("GET", monitorUri, token)
        if not response:
            try:
                response = init_rest_call("GET", monitorUri, token, None, None, True)
            except:
                time.sleep(30)
                response = init_rest_call("GET", monitorUri, token, None, None, True)
        if response["state"] == "COMPLETED":
            if response["result"]["status"] == "FAILED":
                print("---> Activity status FAILED")
                return False
            print(f"---> Activity status {response['state']} {response['progress']}%")
            return True
        elif response["state"] == "ERROR":
            print("\033[91m\033[1m->Action failed:\033[39m", json.dumps(response))
            break
        print(f"---> Activity status {response['state']} {response['progress']}%")
        time.sleep(interval)
    return False


def connect_peer_ppdm(config, ppdmUri, token):
    """Connects remote PPDM system"""
    credsId = add_credentials("POWERPROTECT", config, ppdmUri, token)
    syncPeerUri = f"{ppdmUri}/sync-destination-configuration"
    payload = {
        "name": config["peerPpdmNiceName"],
        "address": config["peerPpdmFQDNorIP"],
        "port": config["peerPpdmPort"],
        "credentialId": credsId,
        "enabled": True,
    }
    response = init_rest_call("POST", syncPeerUri, token, payload)
    if monitor_activity(
        ppdmUri, token, response["activityId"], config["ppdmMonitorTimeout"]
    ):
        print("---> Peer PPDM registered successfully")
        return True
    print("---> Peer PPDM could not be registered")
    return False


def main():
    # Args assignment
    args = get_args()
    configfile, skipOva, justOva = args.configfile, args.skipova, args.justova
    registerVCenter, noVcPlugin = args.regVC, args.noVcPlugin
    addPowerProtectDD, connectPeerPPDM = args.addDD, args.connectPeerPPDM
    ppdmCrossConnect = args.crossConnect

    config = read_config(configfile)

    # Const definition
    apiEndpoint = "/api/v2"
    ppdmApiPort = 8443
    defaultVcPort = 443
    defaultDdPort = 3009
    config["ppdmIpTimeout"] = 300
    config["ppdmApiTimeout"] = 600
    config["ppdmDeployTimeout"] = 600
    config["ppdmMonitorTimeout"] = 180
    username, defaultApiPwd = "admin", "admin"
    config["rootDefaultPwd"] = "changeme"
    config["adminDefaultPwd"] = "@ppAdm1n"
    config["supportDefaultPwd"] = "$upp0rt!"

    if not config["ppdmIpV6"]:
        ppdmIp = config["ppdmIpV4"]
    else:
        ppdmIp = config["ppdmIpV6"]

    # Creates the ovftool command for PPDM deployment
    if not skipOva:
        ppdmOvfExec = create_ovftool_command(config)

        # Executes PPDM OVA Deployment
        print("-> Provisioning PPDM from OVA")
        exec_ova_provisioning(ppdmOvfExec)

    # Breaks the flow if the justOva parameter is specified
    if justOva:
        print("-> Just-ova parameter provided. Exiting")
        raise SystemExit(0)

    # Checking connectivity to PPDM IP and API
    print("-> Checking connectivity to PPDM")
    if not check_connectivity(ppdmIp, config["ppdmIpTimeout"]):
        print(f"---> PPDM IP {ppdmIp} is unreachable")
    else:
        print(f"\033[92m\033[1m---> PPDM IP {ppdmIp} is reachable\033[0m")
        print("-> Checking PPDM API readiness")
        if check_api_accessibility(ppdmIp, config["ppdmApiTimeout"]):
            print("\033[92m\033[1m---> PPDM API is available\033[0m")

    # Logs into the PPDM API
    ppdmUri = f"https://{ppdmIp}:{ppdmApiPort}{apiEndpoint}"
    token = authenticate(ppdmUri, username, defaultApiPwd)

    # Getting PPDM configuration
    print("-> Obtaining PPDM configuration information")
    nodeId = check_deployment(ppdmUri, token)
    deployConfig = get_deploy_config(ppdmUri, token, nodeId)

    # Accepting PPDM EULA
    print("-> Accepting PPDM EULA")
    accept_eula("PPDM", ppdmUri, token)

    # Applying PPDM License
    print("-> Applying license")
    apply_license(config["licenseFile"], ppdmUri, token)

    # Configuring SMTP if applicable
    if config["smtp"]:
        print("-> Applying SMTP settings")
        config_smtp(config, ppdmUri, token)

    # Applying encryption settings
    print("-> Configuring encryption")
    apply_encryption_settings(config, ppdmUri, token)

    # Building deployment configuration
    print("-> Building PPDM deployment configuration")
    config = get_time_zone(config, ppdmUri, token)
    deployConfig = build_deployment_config(config, deployConfig)

    # Deploying PPDM
    print("-> Deploying PPDM")
    if bootstrap_ppdm_deployment(ppdmUri, token, deployConfig):
        result = monitor_deploy_activity(
            ppdmUri,
            token,
            deployConfig["id"],
            config["ppdmDeployTimeout"],
            config["ppdmAdminPwd"],
        )
        if result:
            print("\033[92m\033[1m-> PPDM deployed successfully\033[0m")
        else:
            print("\033[91m\033[1m-> PPDM deployment failed\033[0m")
            raise SystemExit(1)
    else:
        print("\033[91m\033[1m-> PPDM deployment failed\033[0m")
        raise SystemExit(1)

    # Post-install steps - AutoSupport, VC, DD and peer PPDM
    postInstallCheck = False
    if True in (
        config["autoSupport"],
        registerVCenter,
        addPowerProtectDD,
        connectPeerPPDM,
    ):
        postInstallCheck = True
    if postInstallCheck:
        print("-> Initiating post-install tasks")
        # Authenticating based on updated credentials
        token = authenticate(ppdmUri, username, config["ppdmAdminPwd"])
    if config["autoSupport"]:
        print("-> Accepting TELEMETRY EULA")
        accept_eula("TELEMETRY", ppdmUri, token)
        config_auto_support(ppdmUri, token)
    if registerVCenter:
        config["vcPort"] = config.get("vcPort")
        if not config["vcPort"]:
            config["vcPort"] = defaultVcPort
        config["noVcPlugin"] = noVcPlugin
        if config["vcValid"]:
            if accept_certificate("vc", config, ppdmUri, token):
                register_asset_source("VCENTER", config, ppdmUri, token)
        else:
            print("-> Missing vCenter details, skipping vCenter registration")
    if addPowerProtectDD:
        config["ddPort"] = config.get("ddPort")
        if not config["ddPort"]:
            config["ddPort"] = defaultDdPort
        if config["ddValid"]:
            if accept_certificate("dd", config, ppdmUri, token):
                register_asset_source("DATADOMAIN", config, ppdmUri, token)
        else:
            print("-> Missing PowerProtect DD details, skipping DD registration")
    if connectPeerPPDM:
        config["peerPpdmPort"] = config.get("peerPpdmPort")
        if not config["peerPpdmPort"]:
            config["peerPpdmPort"] = ppdmApiPort
        if config["peerPpdmValid"]:
            if accept_certificate("peerPpdm", config, ppdmUri, token):
                print("-> Connecting peer PPDM host")
                qrEnabled = connect_peer_ppdm(config, ppdmUri, token)
        else:
            print("-> Missing peer PPDM details, skipping configuration")
            qrEnabled = False
    else:
        qrEnabled = False
    # Configuring bi-directional communication only if selected and peer PPDM is connected
    if qrEnabled and ppdmCrossConnect:
        print("-> Configuring bi-directional replication direction")
        # Authenticating and operating against peer PPDM
        peerPpdmUri = f"https://{config['peerPpdmFQDNorIP']}:{ppdmApiPort}{apiEndpoint}"
        peerToken = authenticate(
            peerPpdmUri, config["peerPpdmUser"], config["peerPpdmPassword"]
        )
        peerConfig = {"peerPpdmFQDNorIP": config["ppdmFQDN"]}
        peerConfig["peerPpdmPort"] = "8443"
        peerConfig["peerPpdmUser"] = "admin"
        peerConfig["peerPpdmPassword"] = config["ppdmAdminPwd"]
        peerConfig["peerPpdmNiceName"] = "PPDM" + config["ppdmFQDN"].split(".")[0]
        if accept_certificate("peerPpdm", peerConfig, peerPpdmUri, peerToken):
            connect_peer_ppdm(peerConfig, peerPpdmUri, peerToken)

    print("\033[92m\033[1m-> All tasks have been completed\033[0m")


if __name__ == "__main__":
    main()
