#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import platform
import subprocess
import time
import socket
import requests
import urllib3


# This script purpose is to automate PowerProtect Data Manager deployment
# Author - Idan Kentor <idan.kentor@dell.com>
# Copyright [2026] [Idan Kentor]

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
        "-configfile", "-c", "--config-file",
        required=True,
        dest="config_file",
        help="Full path to the JSON config file",
    )
    ova_group = parser.add_mutually_exclusive_group()
    ova_group.add_argument(
        "-skipova", "--skip-ova",
        dest="skip_ova",
        action="store_true",
        help="Skip OVA deployment",
    )
    ova_group.add_argument(
        "-justova", "--just-ova",
        dest="just_ova",
        action="store_true",
        help="Stop after OVA deployment",
    )

    parser.add_argument(
        "-vc", "--register-vcenter",
        dest="register_vc",
        action="store_true",
        help="Register vCenter in PPDM",
    )

    parser.add_argument(
        "-novcplugin", "--prevent-plugin-install",
        dest="no_vc_plugin",
        action="store_false",
        help="Prevent vCenter plugin deployment",
    )

    parser.add_argument(
        "-dd", "--add-dd",
        required=False,
        dest="add_dd",
        action="store_true",
        help="Add Data Domain to PPDM",
    )

    parser.add_argument(
        "-ppdm", "--connect-ppdm",
        required=False,
        dest="connect_peer",
        action="store_true",
        help="Connect remote PPDM system",
    )

    parser.add_argument(
        "-cross", "--bi-directional",
        dest="cross_connect",
        action="store_true",
        help="Configure bi-directional \
                            communication between the two PPDM systems",
    )

    args = parser.parse_args()
    return args


def read_config(config_file):
    """Reads config file, validates params and assigns to the config dict"""

    with open(config_file, "r", encoding="utf-8") as file_handle:
        try:
            config = json.load(file_handle)
        except json.decoder.JSONDecodeError as error:
            print("-> Cannot parse JSON config file:", {error})
            raise SystemExit(1) from error
    file_handle.close()

    for key in list(config.keys()):
        if key.startswith("_comment"):
            config.pop(key)

    config["ppdmIpV6"] = config.get("ppdmIpV6", False)

    if config["ppdmIpV6"]:
        if not config.get("ppdmIpV6Netmask") or not config.get("ppdmIpV6Gateway"):
            print("-> Missing IPv6 configuration parameters")
            raise SystemExit(1)

    if not config["ppdmIpV6"]:
        config["ppdmIpV4"] = config.get("ppdmIpV4", False)
        if not config["ppdmIpV4"]:
            print("->Missing PPDM IPv4 address")
            raise SystemExit(1)
        config["ppdmIpV4Netmask"] = config.get("ppdmIpV4Netmask", False)
        config["ppdmIpv4Gateway"] = config.get("ppdmIpv4Gateway", False)
        if not config["ppdmIpV4Netmask"] or not config["ppdmIpv4Gateway"]:
            print("->Missing IPv4 configuration parameters")
            raise SystemExit(1)

    if not config.get("ppdmDatastore"):
        print("->No Datastore provided, specify DS for PPDM")
        raise SystemExit(1)

    if not config.get("ppdmMgmtNetwork"):
        print("->Management Network Port Group must be specified")
        raise SystemExit(1)

    if not config.get("ntpServers") or not config.get("dnsServers"):
        print("->Missing DNS or NTP IP addresses")
        raise SystemExit(1)

    config["ntpServers"] = config["ntpServers"][0].split(", ")
    config["dnsServers"] = config["dnsServers"][0].split(", ")
    config["license_file"] = config.get("license_file", "trial")

    for encrypt_type in ("protectionEncryption", "replicationEncryption"):
        config[encrypt_type] = config.get(encrypt_type, True)

    if not isinstance(config[encrypt_type], bool):
        print(f"-> invalid value for {encrypt_type}")
        raise SystemExit(1)

    for asset in ("vc", "dd", "peerPpdm"):
        fqdn_ip = config.get(f"{asset}FQDNorIP")
        user = config.get(f"{asset}User")
        password = config.get(f"{asset}Password")

        valid = all((fqdn_ip, user, password))
        config[f"{asset}Valid"] = bool(valid)
        if not valid:
            continue
        if isinstance(fqdn_ip, str) and fqdn_ip and fqdn_ip[0].isdigit():
            parts = fqdn_ip.split(".")
            segment = parts[3] if len(parts) > 3 else parts[-1]
            config[f"{asset}NiceName"] = f"{asset.upper()}{segment}"
        else:
            if isinstance(fqdn_ip, str):
                config[f"{asset}NiceName"] = fqdn_ip.split(".")[0]
            else:
                config[f"{asset}NiceName"] = str(fqdn_ip)

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

    ppdm_exec = f'{config["ovfToolLocation"]} --noDestinationSSLVerify --skipManifestCheck --acceptAllEulas --powerOn --name="{config["ppdmVmName"]}" '
    ppdm_exec += f'--diskMode=thin --datastore={config["ppdmDatastore"]} --net:"VM Network"="{config["ppdmMgmtNetwork"]}" '

    if not config["ppdmIpV6"]:
        ppdm_exec += f'--prop:vami.ip0.brs={config["ppdmIpV4"]} --prop:vami.netmask0.brs="{config["ppdmIpV4Netmask"]}" --prop:vami.gateway.brs="{config["ppdmIpv4Gateway"]}" '
    else:
        ppdm_exec += f'--prop:vami.ip0.brs={config["ppdmIpV6"]} --prop:vami.netmask0.brs="{config["ppdmIpV6Netmask"]}" --prop:vami.gateway.brs="{config["ppdmIpV6Gateway"]}" '

    ppdm_exec += f'--prop:vami.DNS.brs="{", ".join(config["dnsServers"])}" --prop:vami.fqdn.brs="{config["ppdmFQDN"]}" '
    ppdm_exec += f'--deploymentOption="{config["platform"]}" "{config["ppdmOVALocation"]}" '
    ppdm_exec += f'vi://"{config["vcUser"]}":"{config["vcPassword"]}"@{config["vcFQDNorIP"]}/{config["datacenter"]}/host/{config["esxCluster"]}/'

    return ppdm_exec


def exec_ova_provisioning(ovf_exec):
    """Executes ovftool deployment command"""
    exit_code = os.system(ovf_exec)

    if exit_code == 0:
        print("---> OVA deployment completed successfully")
    else:
        print("---> OVA deployment failed")
        raise SystemExit(1)


def tcp_check(ip_address):
    """Perform TCP connect check to a given IP address"""
    port = 443
    timeout = 3

    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_connectivity(ip_address, ppdm_api_timeout):
    """Generic call to check connectivity to a given IP address"""
    interval = 10
    start = time.monotonic()

    if platform.system().lower() == "windows":
        ping_cmd = f"ping {ip_address} -n 3"
    else:
        ping_cmd = f"ping {ip_address} -c 3"

    while True:
        if (time.monotonic() - start) > ppdm_api_timeout:
            return False
        result = subprocess.run(
            ping_cmd, shell=True, stdout=subprocess.PIPE, check=False
        )
        if result.returncode == 0:
            return True
        if tcp_check(ip_address):
            return True

        time.sleep(interval)


def check_api_accessibility(ppdm_ip, ppdm_api_timeout):
    """Continuously checks if PPDM API is available"""
    api_endpoint = f"https://{ppdm_ip}/eula.html"
    interval = 30
    start = time.monotonic()

    while True:
        if (time.monotonic() - start) > ppdm_api_timeout:
            print("PPDM API check timed out. Exiting")
            raise SystemExit(1)
        if init_rest_call("GET", api_endpoint, None, None, None, True):
            return True
        print("---> PPDM API is unreachable. Retrying")
        time.sleep(interval)


def init_rest_call(verb, uri, token, payload=None, params=None, deploy=None):
    """Generic function for REST calls"""
    code = {200, 201, 202, 204}
    verify = False
    timeout = 90

    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {token}"}

    if uri.endswith("/login") or deploy:
        headers = {"Content-Type": "application/json"}

    payload = json.dumps(payload)

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

    except requests.exceptions.ConnectionError as error:
        if deploy:
            return False
        print(f"->Error Connecting to {uri}: {error}")
        raise SystemExit(1) from error
    except requests.exceptions.Timeout as error:
        print(f"->Connection timed out {urllib3}: {error}")
        raise SystemExit(1) from error
    except requests.exceptions.RequestException as error:
        if deploy and response.status_code in (401, 502):
            return False
        print(
            f"->The call {response.request.method} {response.url} failed with exception:{error}"
        )

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
    except ValueError:
        return response.content


def check_deployment(ppdm_uri, token):
    """Validate that PPDM is ready for deployment"""
    nodes_uri = f"{ppdm_uri}/nodes"

    nodes = init_rest_call("GET", nodes_uri, token)

    if not nodes or "content" not in nodes:
        raise SystemExit("Cannot query the Data Manager server. Exiting...")

    if nodes["content"][0]["status"] != "PENDING":
        raise SystemExit("PPDM is not available for deployment. Exiting...")

    print("---> PPDM is deployment ready")
    return nodes["content"][0]["id"]


def get_deploy_config(ppdm_uri, token, node_id):
    """Retrieve PPDM deployment configuration"""
    config_uri = f"{ppdm_uri}/configurations"
    desired_config = False

    deploy_config = init_rest_call("GET", config_uri, token)

    if not deploy_config or "content" not in deploy_config:
        raise SystemExit("Cannot query the Data Manager server. Exiting...")

    for config_item in deploy_config.get("content"):
        if config_item.get("nodeId") == node_id:
            desired_config = config_item

    if not desired_config:
        print("Could not detect a valid configuration. Exiting.")
        raise SystemExit(1)

    return desired_config


def accept_eula(eula_type, ppdm_uri, token):
    """Accept PPDM EULAs by type"""
    eula_uri = f"{ppdm_uri}/eulas/{eula_type}"

    payload = {"accepted": True}

    response = init_rest_call("PATCH", eula_uri, token, payload)

    if not response.get("accepted"):
        print(f"{eula_type} EULA could not be accepted, exiting...")
        raise SystemExit(1)

    print(f"---> {eula_type} EULA accepted")
    return True


def apply_license(license_file, ppdm_uri, token):
    """Apply PPDM license from file"""
    if license_file.strip().lower() == "trial":
        print("-> Using Trial license")
        return True

    try:
        with open(license_file, "r", encoding="utf-8") as file_handle:
            license_content = file_handle.read().strip()
    except (OSError, FileNotFoundError):
        print("-> Could not read license file. Using Trial license")
        return True

    if not license_content:
        print("-> License file is empty. Using Trial license")
        return True

    license_uri = f"{ppdm_uri}/licenses"
    payload = {"type": "CAPACITY", "key": license_content}

    response = init_rest_call("POST", license_uri, token, payload)

    if response.get("status") == "VALID":
        print("-> Using Capacity license")
        return True

    print("-> License not accepted. Using Trial license")
    return False


def config_smtp(config, ppdm_uri, token):
    """Apply SMTP settings"""
    smtp_uri = f"{ppdm_uri}/smtp"

    payload = {
        "mailServer": config["smtpMailServer"],
        "mailFrom": config["smtpMailFrom"],
        "port": config["smtpPort"],
    }

    if config["smtpAuth"]:
        payload["username"] = config["smtpUser"]
        payload["password"] = config["smtpPassword"]

    response = init_rest_call("POST", smtp_uri, token, payload)

    if "id" in response:
        return True

    print("Could not apply SMTP settings. Exiting")
    return False


def apply_encryption_settings(config, ppdm_uri, token):
    """Apply encryption settings"""
    encr_uri = f"{ppdm_uri}/common-settings/ENCRYPTION_SETTING"

    encr_payload = {"id": "ENCRYPTION_SETTING"}
    protect_encrypt = {
        "name": "enableProtectionEncryption",
        "value": str(config["protectionEncryption"]).lower(),
        "type": "BOOLEAN",
    }
    replication_encrypt = {
        "name": "enableReplicationEncryption",
        "value": str(config["replicationEncryption"]).lower(),
        "type": "BOOLEAN",
    }

    encr_payload["properties"] = [protect_encrypt, replication_encrypt]

    response = init_rest_call("PUT", encr_uri, token, encr_payload)

    try:
        if response["id"] != encr_payload["id"]:
            print("Could not apply encryption settings. Exiting")
            raise SystemExit(1)
        for setting in response["properties"]:
            if setting["name"] == "enableProtectionEncryption":
                if config["replicationEncryption"] != bool(
                    setting["value"]
                ):
                    print("Could not apply encryption settings. Exiting")
                    raise SystemExit(1)
            elif setting["name"] == "enableReplicationEncryption":
                if config["protectionEncryption"] != bool(
                    setting["value"]
                ):
                    print("Could not apply encryption settings. Exiting")
                    raise SystemExit(1)
    except KeyError:
        print("Could not apply encryption settings. Exiting")
        raise SystemExit(1) from KeyError

    return True


def get_time_zone(config, ppdm_uri, token):
    """Determine the time zone"""
    local_tz = datetime.datetime.now().astimezone().tzinfo
    local_tz_name = str(local_tz).split(" ", maxsplit=1)[0]

    config["timeZone"] = (config.get("timeZone")
                          or config.get("time_zone")
                          or local_tz_name)

    timezones = {"eastern": "EST",
                 "et": "EST",
                 "central": "CST6CDT",
                 "ct": "CST6CDT",
                 "pacific": "PST8PDT",
                 "pt": "PST8PDT",
                 "etc": "Etc/UTC"}

    normalized = timezones.get(config["timeZone"].lower(), config["timeZone"])
    config["timeZone"] = normalized

    timezone_uri = f"{ppdm_uri}/timezones"
    tz_list = init_rest_call("GET", timezone_uri, token)

    content = tz_list.get("content") if isinstance(tz_list, dict) else None
    if isinstance(content, list):
        for tz in content:
            tz_name = tz.get("name", "")
            if config["timeZone"] in tz_name:
                config["timeZone"] = tz.get("id", config["timeZone"])
                break

    print(f"-> Time zone detected: {config['timeZone']}")
    return config


def build_deployment_config(config, deploy_config):
    """Form the PPDM deployment config"""
    deploy_config["timeZone"] = config["timeZone"]

    for network in deploy_config["networks"]:
        if "nslookupSuccess" in network:
            if network["nslookupSuccess"]:
                print("-> Name resolution completed successfully")
            else:
                print("-> Warning: name resolution issues")
            break

    deploy_config["ntpServers"] = config["ntpServers"]

    for user in deploy_config.get("osUsers"):
        user["password"] = config[user["userName"] + "DefaultPwd"]
        user["newPassword"] = config["ppdmAdminPwd"]

    deploy_config["applicationUserPassword"] = config["ppdmAdminPwd"]

    if config["autoSupport"]:
        deploy_config["autoSupport"] = True

    deploy_config["gettingStartedCompleted"] = True
    return deploy_config


def bootstrap_ppdm_deployment(ppdm_uri, token, deploy_config):
    """Initiates the PPDM deployment"""
    deploy_uri = f"{ppdm_uri}/configurations/{deploy_config['id']}"

    deploy_response = init_rest_call("PUT", deploy_uri, token, deploy_config)

    return deploy_response


def monitor_deploy_activity(
    ppdm_uri, token, deploy_config_id, ppdm_deploy_timeout, admin_pwd
):
    """Monitors deployment operation"""
    monitor_uri = f"{ppdm_uri}/configurations/{deploy_config_id}/config-status"

    poll_interval = 5
    retry_interval = 30
    start = time.monotonic()

    requires_auth = False
    username = "admin"

    print(f"---> Deploying configuration {deploy_config_id}")

    while True:
        if (time.monotonic() - start) > ppdm_deploy_timeout:
            break
        response = init_rest_call("GET", monitor_uri, token)

        if not response:
            if not requires_auth:
                response = init_rest_call("GET", monitor_uri, token, None, None, True)
            else:
                token = authenticate(ppdm_uri, username, admin_pwd)
                try:
                    response = init_rest_call(
                        "GET", monitor_uri, token, None, None, True
                    )
                except requests.exceptions.RequestException:
                    time.sleep(retry_interval)
                    response = init_rest_call(
                        "GET", monitor_uri, token, None, None, True
                    )
                requires_auth = True
        status = response.get("status")
        percent_complete = response.get("percentageCompleted", 0)
        if status == "SUCCESS":
            print(f"---> Deployment status {status} {percent_complete}%")
            return True
        if status == "ERROR":
            print("->Action failed:", json.dumps(response))
            break
        print(f"---> Deployment status {status} {percent_complete}%")
        time.sleep(poll_interval)

    return False


def authenticate(ppdm_uri, username, password):
    """Login to PowerProtect Data Manager"""
    login_uri = f"{ppdm_uri}/login"

    login_payload = {"username": username, "password": password}
    token = init_rest_call("POST", login_uri, login_payload, login_payload)

    return token


def accept_certificate(asset_type, config, ppdm_uri, token):
    """Accept host certificate"""
    certs_uri = f"{ppdm_uri}/certificates"

    params = {
        "host": config[asset_type + "FQDNorIP"],
        "port": config[asset_type + "Port"],
        "type": "HOST",
    }

    certs = init_rest_call("GET", certs_uri, token, None, params)

    if not certs or not isinstance(certs, list):
        print(f"-> No certificate response for {asset_type.upper()}")
        return False

    cert = certs[0]
    cert_id = cert.get("id")

    if not cert_id:
        print(f"-> Certificate response missing 'id' for {asset_type.upper()}")
        return False

    if cert.get("state") == "ACCEPTED":
        return True

    cert["state"] = "ACCEPTED"
    cert_upd_uri = f"{certs_uri}/{cert_id}"
    cert = init_rest_call("PUT", cert_upd_uri, token, cert)

    if isinstance(cert, dict):
        if cert.get("state") == "ACCEPTED":
            return True
    elif bool(cert):
        return True

    print(f"Cannot add {asset_type.upper()}. Could not accept certificate")
    return False


def add_credentials(asset_type, config, ppdm_uri, token):
    """Add credentials for a given asset source type"""
    asset_type_alt = None

    creds_uri = f"{ppdm_uri}/credentials"

    if asset_type == "VCENTER":
        asset_type_alt = "vc"
    elif asset_type == "DATADOMAIN":
        asset_type_alt = "dd"
    elif asset_type == "POWERPROTECT":
        asset_type_alt = "peerPpdm"

    payload = {"type": asset_type,
               "name": config[asset_type_alt + "NiceName"],
               "username": config[asset_type_alt + "User"],
               "password": config[asset_type_alt + "Password"]}

    response = init_rest_call("POST", creds_uri, token, payload)

    if "id" in response:
        return response["id"]

    return False


def config_auto_support(ppdm_uri, token):
    """Configure AutoSupport"""
    support_uri = f"{ppdm_uri}/common-settings/TELEMETRY_SETTING"

    response = init_rest_call("GET", support_uri, token)
    if not isinstance(response, dict):
        print("-> AutoSupport could not be configured")
        return False

    properties = response.get("properties")
    if not isinstance(properties, list) or not response.get("id"):
        print("-> AutoSupport could not be configured")
        return False

    for element in properties:
        if element.get("name") == "transportType":
            element["value"] = "EMAIL"

    response.pop("_links", None)
    payload = response
    response = init_rest_call("PUT", support_uri, token, payload)

    if response.get("id"):
        print("-> AutoSupport configured successfully")
        return True

    print("-> AutoSupport could not be configured")
    return False


def register_asset_source(asset_type, config, ppdm_uri, token):
    """Register asset source"""
    asset_type_alt = asset_type_alt2 = None

    if asset_type == "VCENTER":
        asset_type_alt = "vc"
        asset_type_alt2 = "vCenter"
    elif asset_type == "DATADOMAIN":
        asset_type_alt = "dd"
        asset_type_alt2 = "Data Domain"
    else:
        print(f"Unsupported asset source type: {asset_type}")
        return False

    creds_id = add_credentials(asset_type, config, ppdm_uri, token)

    if not creds_id:
        print(f"Could not add {asset_type_alt2} credentials")
        return False

    asset_source_id = f"{ppdm_uri}/inventory-sources"

    payload = {
        "type": asset_type,
        "name": config[f"{asset_type_alt}NiceName"],
        "address": config[f"{asset_type_alt}FQDNorIP"],
        "port": config[f"{asset_type_alt}Port"],
        "credentials": {"id": creds_id},
    }

    if asset_type == "DATADOMAIN":
        payload["type"] = "EXTERNALDATADOMAIN"
    elif asset_type == "VCENTER":
        vc_details = {"hosting": True,
                      "vSphereUiIntegration": config["noVcPlugin"]}
        payload["details"] = {"vCenter": vc_details}

    response = init_rest_call("POST", asset_source_id, token, payload)

    if isinstance(response, dict) and response.get("id"):
        print(f"-> {asset_type_alt2} registered successfully")
        details = response.get("details")
        vc = details.get("vCenter") if isinstance(details, dict) else None
        if isinstance(vc, dict):
            if vc.get("hosting"):
                print("--> Hosting vCenter configured successfully")
            if not config["noVcPlugin"] and not vc.get("vSphereUiIntegration"):
                print("--> PPDM vCenter plugin installation was skipped")
        return True

    print(f"-> {asset_type_alt2} could not be registered")
    return False


def monitor_activity(ppdm_uri, token, activity_id, ppdm_monitor_timeout):
    """Continuously monitor activity by ID"""
    monitor_uri = f"{ppdm_uri}/activities/{activity_id}"
    interval = 5
    start = time.monotonic()

    print(f"---> Monitoring activity ID {activity_id}")

    while True:
        if (time.monotonic() - start) > ppdm_monitor_timeout:
            break
        response = init_rest_call("GET", monitor_uri, token)
        if not response:
            try:
                response = init_rest_call("GET", monitor_uri, token, None, None, True)
            except (SystemExit, requests.exceptions.RequestException):
                time.sleep(30)
                response = init_rest_call("GET", monitor_uri, token, None, None, True)
        state = response.get("state")
        progress = response.get("progress")
        if state == "COMPLETED":
            result = response.get("result")
            if result.get("status") == "FAILED":
                print("---> Activity status FAILED")
                return False
            print(f"---> Activity status {state} {progress}%")
            return True
        if state == "ERROR":
            print("->Action failed:", json.dumps(response))
            break
        print(f"---> Activity status {state} {progress}%")
        time.sleep(interval)

    return False


def connect_peer_ppdm(config, ppdm_uri, token):
    """Connect remote PPDM system"""
    monitor_timeout = config["ppdmMonitorTimeout"]
    cred_id = add_credentials("POWERPROTECT", config, ppdm_uri, token)
    sync_peer_uri = f"{ppdm_uri}/sync-destination-configuration"

    payload = {
        "name": config["peerPpdmNiceName"],
        "address": config["peerPpdmFQDNorIP"],
        "port": config["peerPpdmPort"],
        "credentialId": cred_id,
        "enabled": True
    }

    response = init_rest_call("POST", sync_peer_uri, token, payload)

    if isinstance(response, dict) and response.get("activityId"):
        activity_id = response.get("activityId")
        if monitor_activity(ppdm_uri, token, activity_id, monitor_timeout):
            print("---> Peer PPDM registered successfully")
            return True

    print("---> Peer PPDM could not be registered")
    return False


def main():
    # Args assignment
    args = get_args()
    config_file, skip_ova = args.config_file, args.skip_ova
    just_ova, register_vc = args.just_ova, args.register_vc
    no_vc_plugin, add_dd = args.no_vc_plugin, args.add_dd
    connect_peer, ppdm_cross_connect = args.connect_peer, args.cross_connect

    config = read_config(config_file)

    # Const definition
    api_endpoint = "/api/v2"
    ppdm_api_port = 8443
    default_vc_port = 443
    default_dd_port = 3009
    config["ppdmIpTimeout"] = 300
    config["ppdm_api_timeout"] = 1200
    config["ppdmDeployTimeout"] = 600
    config["ppdmMonitorTimeout"] = 180
    username, default_api_pwd = "admin", "admin"
    config["rootDefaultPwd"] = "changeme"
    config["adminDefaultPwd"] = "@ppAdm1n"
    config["supportDefaultPwd"] = "$upp0rt!"
    qr_enabled = False

    if not config["ppdmIpV6"]:
        ppdm_ip = config["ppdmIpV4"]
    else:
        ppdm_ip = config["ppdmIpV6"]

    # Create the ovftool command for PPDM deployment
    if not skip_ova:
        ppdm_ovf_exec = create_ovftool_command(config)
        # Execute PPDM OVA Deployment
        print("-> Provisioning PPDM from OVA")
        exec_ova_provisioning(ppdm_ovf_exec)

    # Break the flow if the justOva parameter is specified
    if just_ova:
        print("-> Just-ova parameter provided. Exiting")
        raise SystemExit(0)

    # Check connectivity to PPDM IP and API
    print("-> Checking connectivity to PPDM")
    if not check_connectivity(ppdm_ip, config["ppdmIpTimeout"]):
        print(f"---> PPDM IP {ppdm_ip} is unreachable")
    else:
        print(f"---> PPDM IP {ppdm_ip} is reachable")
        print("-> Checking PPDM API readiness")
        if check_api_accessibility(ppdm_ip, config["ppdm_api_timeout"]):
            print("---> PPDM API is available")

    # Login to the PPDM API
    ppdm_uri = f"https://{ppdm_ip}:{ppdm_api_port}{api_endpoint}"
    token = authenticate(ppdm_uri, username, default_api_pwd)

    # Get PPDM configuration
    print("-> Obtaining PPDM configuration information")
    node_id = check_deployment(ppdm_uri, token)
    deploy_config = get_deploy_config(ppdm_uri, token, node_id)

    # Accept PPDM EULA
    print("-> Accepting PPDM EULA")
    accept_eula("PPDM", ppdm_uri, token)

    # Apply PPDM License
    print("-> Applying license")
    apply_license(config["license_file"], ppdm_uri, token)

    # Configure SMTP
    if config["smtp"]:
        print("-> Applying SMTP settings")
        config_smtp(config, ppdm_uri, token)

    # Apply encryption settings
    print("-> Configuring encryption")
    apply_encryption_settings(config, ppdm_uri, token)

    # Build deployment configuration
    print("-> Building PPDM deployment configuration")
    config = get_time_zone(config, ppdm_uri, token)
    deploy_config = build_deployment_config(config, deploy_config)

    # Deploy PPDM
    print("-> Deploying PPDM")
    if bootstrap_ppdm_deployment(ppdm_uri, token, deploy_config):
        result = monitor_deploy_activity(
            ppdm_uri,
            token,
            deploy_config["id"],
            config["ppdmDeployTimeout"],
            config["ppdmAdminPwd"],
        )
        if result:
            print("-> PPDM deployed successfully")
        else:
            print("-> PPDM deployment failed")
            raise SystemExit(1)
    else:
        print("-> PPDM deployment failed")
        raise SystemExit(1)

    # Post-install steps - AutoSupport, VC, DD and peer PPDM
    post_install_check = False
    if True in (
        config["autoSupport"],
        register_vc,
        add_dd,
        connect_peer,
    ):
        post_install_check = True
    if post_install_check:
        print("-> Initiating post-install tasks")
        token = authenticate(ppdm_uri, username, config["ppdmAdminPwd"])
    if config["autoSupport"]:
        print("-> Accepting TELEMETRY EULA")
        accept_eula("TELEMETRY", ppdm_uri, token)
        config_auto_support(ppdm_uri, token)
    if register_vc:
        config["vcPort"] = config.get("vcPort")
        if not config["vcPort"]:
            config["vcPort"] = default_vc_port
        config["noVcPlugin"] = no_vc_plugin
        if config["vcValid"]:
            if accept_certificate("vc", config, ppdm_uri, token):
                register_asset_source("VCENTER", config, ppdm_uri, token)
        else:
            print("-> Missing vCenter details, skipping vCenter registration")
    if add_dd:
        config["ddPort"] = config.get("ddPort")
        if not config["ddPort"]:
            config["ddPort"] = default_dd_port
        if config["ddValid"]:
            if accept_certificate("dd", config, ppdm_uri, token):
                register_asset_source("DATADOMAIN", config, ppdm_uri, token)
        else:
            print("-> Missing Data Domain details, skipping DD registration")
    if connect_peer:
        config["peerPpdmPort"] = config.get("peerPpdmPort")
        if not config["peerPpdmPort"]:
            config["peerPpdmPort"] = ppdm_api_port
        if config["peerPpdmValid"]:
            if accept_certificate("peerPpdm", config, ppdm_uri, token):
                print("-> Connecting peer PPDM host")
                qr_enabled = connect_peer_ppdm(config, ppdm_uri, token)
        else:
            print("-> Missing peer PPDM details, skipping configuration")
            qr_enabled = False
    else:
        qr_enabled = False
    # Configure bi-directional communication only if selected and there is a peer PPDM
    if qr_enabled and ppdm_cross_connect:
        print("-> Configuring bi-directional replication direction")
        peer_ppdm_uri = f"https://{config['peerPpdmFQDNorIP']}:{ppdm_api_port}{api_endpoint}"
        peer_token = authenticate(
            peer_ppdm_uri, config["peerPpdmUser"], config["peerPpdmPassword"]
        )
        peer_config = {"peerPpdmFQDNorIP": config["ppdmFQDN"]}
        peer_config["peerPpdmPort"] = "8443"
        peer_config["peerPpdmUser"] = "admin"
        peer_config["peerPpdmPassword"] = config["ppdmAdminPwd"]
        peer_config["peerPpdmNiceName"] = "PPDM" + config["ppdmFQDN"].split(".")[0]
        if accept_certificate("peerPpdm", peer_config, peer_ppdm_uri, peer_token):
            connect_peer_ppdm(peer_config, peer_ppdm_uri, peer_token)

    print("-> All tasks have been completed")


if __name__ == "__main__":
    main()
