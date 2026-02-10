#!/usr/bin/env python3
"""PowerProtect Data Manager Deployment Automation Script.

This script automates the deployment of Dell PowerProtect Data Manager
in VMware vSphere environments using either ovftool or govc.

Author: Idan Kentor <idan.kentor@dell.com>
Copyright: [2026] [Idan Kentor]

Example Usage:
    python ppdm_deploy.py -configfile ppdm-config-minimal.json
    python ppdm_deploy.py -configfile ppdm-prod-config.json -vc -dd
    python ppdm_deploy.py -configfile ppdm-prod-config.json -vc -dd -ppdm
    python ppdm_deploy.py -configfile ppdm-config.json -vc -dd -ppdm -cross
    python ppdm_deploy.py -configfile ppdm-prod-config.json -skipova
    python ppdm_deploy.py -configfile ppdm_test.json -justova
    python ppdm_deploy.py -configfile ppdm-prod-config.json -tool govc
"""

import argparse
import datetime
import json
import logging
import logging.handlers
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
import requests
import urllib3

urllib3.disable_warnings()

logger = logging.getLogger("ppdm_deploy")


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
        logger.info("PPDM Deployment Script Started")
        logger.info("Execution Time: %s",
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("Script: PowerProtect Data Manager Deployment Automation")
        logger.info("Command: %s", " ".join(sys.argv))
        logger.info(separator)

    except (OSError, IOError) as e:
        print(f"-> Could not create log file: {e}")

    return logger


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
        help="Configure bi-directional communication "
             "between the two PPDM systems",
    )

    parser.add_argument(
        "-tool", "--deployment-tool",
        choices=["ovftool", "govc"],
        default="ovftool",
        help="Choose deployment tool: ovftool (default) or govc"
    )

    args = parser.parse_args()
    return args


def read_config(config_file):
    """Reads config file, validates params and assigns to the config dict"""

    with open(config_file, "r", encoding="utf-8") as file_handle:
        try:
            config = json.load(file_handle)
        except json.decoder.JSONDecodeError as error:
            print(f"-> Cannot parse JSON config file: {error}")
            logger.error("Cannot parse JSON config file: %s", error)
            raise SystemExit(1) from error

    for key in list(config.keys()):
        if key.startswith("_comment"):
            config.pop(key)

    config["ppdmIpV6"] = config.get("ppdmIpV6", False)

    if config["ppdmIpV6"]:
        ipv6_netmask = config.get("ppdmIpV6Netmask")
        ipv6_gateway = config.get("ppdmIpV6Gateway")
        if not ipv6_netmask or not ipv6_gateway:
            print("-> Missing IPv6 configuration parameters")
            logger.error("Missing IPv6 configuration parameters")
            raise SystemExit(1)

    if not config["ppdmIpV6"]:
        config["ppdmIpV4"] = config.get("ppdmIpV4", False)
        if not config["ppdmIpV4"]:
            print("-> Missing PPDM IPv4 address")
            logger.error("Missing PPDM IPv4 address")
            raise SystemExit(1)
        config["ppdmIpV4Netmask"] = config.get("ppdmIpV4Netmask", False)
        config["ppdmIpv4Gateway"] = config.get("ppdmIpv4Gateway", False)
        if not config["ppdmIpV4Netmask"] or not config["ppdmIpv4Gateway"]:
            print("-> Missing IPv4 configuration parameters")
            logger.error("Missing IPv4 configuration parameters")
            raise SystemExit(1)

    if not config.get("ppdmDatastore"):
        print("-> No Datastore provided, specify DS for PPDM")
        logger.error("No Datastore provided, specify DS for PPDM")
        raise SystemExit(1)

    if not config.get("ppdmMgmtNetwork"):
        print("-> Management Network Port Group must be specified")
        logger.error("Management Network Port Group must be specified")
        raise SystemExit(1)

    if not config.get("ntpServers") or not config.get("dnsServers"):
        print("-> Missing DNS or NTP IP addresses")
        logger.error("Missing DNS or NTP IP addresses")
        raise SystemExit(1)

    config["ntpServers"] = config["ntpServers"][0].split(", ")
    config["dnsServers"] = config["dnsServers"][0].split(", ")
    config["license_file"] = config.get("license_file", "trial")
    config["logFile"] = config.get("logFile", "ppdm_deploy.log")

    for encrypt_type in ("protectionEncryption", "replicationEncryption"):
        config[encrypt_type] = config.get(encrypt_type, True)

    if not isinstance(config[encrypt_type], bool):
        print(f"-> invalid value for {encrypt_type}")
        logger.error("invalid value for %s", encrypt_type)
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

    smtp_keys = ("smtpMailServer", "smtpMailFrom", "smtpPort")
    if all(key in config for key in smtp_keys):
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
    logger.info("Creating OVF tool command")

    ovf_tool = config["ovfToolLocation"]
    ppdm_exec = (
        f'{ovf_tool} --noDestinationSSLVerify --skipManifestCheck '
        f'--acceptAllEulas --powerOn --name="{config["ppdmVmName"]}" '
        f'--diskMode=thin --datastore={config["ppdmDatastore"]} '
        f'--net:"VM Network"="{config["ppdmMgmtNetwork"]}" '
    )

    if not config["ppdmIpV6"]:
        ppdm_exec += (
            f'--prop:vami.ip0.brs={config["ppdmIpV4"]} '
            f'--prop:vami.netmask0.brs="{config["ppdmIpV4Netmask"]}" '
            f'--prop:vami.gateway.brs="{config["ppdmIpv4Gateway"]}" '
        )
    else:
        ppdm_exec += (
            f'--prop:vami.ip0.brs={config["ppdmIpV6"]} '
            f'--prop:vami.netmask0.brs="{config["ppdmIpV6Netmask"]}" '
            f'--prop:vami.gateway.brs="{config["ppdmIpV6Gateway"]}" '
        )

    ppdm_exec += (
        f'--prop:vami.DNS.brs="{", ".join(config["dnsServers"])}" '
        f'--prop:vami.fqdn.brs="{config["ppdmFQDN"]}" '
        f'--deploymentOption="{config["platform"]}" '
        f'"{config["ppdmOVALocation"]}" vi://'
        f'"{config["vcUser"]}":"{config["vcPassword"]}"@'
        f'{config["vcFQDNorIP"]}/{config["datacenter"]}/'
        f'host/{config["esxCluster"]}/'
    )

    safe_exec = ppdm_exec.replace(config["vcPassword"], "*** REDACTED ***")
    logger.info("OVF Tool command: %s", safe_exec)

    return ppdm_exec


def create_govc_command(config):
    """Generate govc command with JSON spec for PPDM deployment"""
    logger.info("Creating govc command")

    spec = {
        "DiskProvisioning": "thin",
        "IPAllocationPolicy": "fixedPolicy",
        "IPProtocol": "IPv4",
        "MarkAsTemplate": False,
        "Name": config["ppdmVmName"],
        "NetworkMapping": [
            {
                "Name": "VM Network",
                "Network": config["ppdmMgmtNetwork"]
            }
        ],
        "PowerOn": True,
        "WaitForIP": False
    }

    if not config["ppdmIpV6"]:
        spec["PropertyMapping"] = [
            {
                "Key": "vami.ip0.PPDM",
                "Value": config["ppdmIpV4"]
            },
            {
                "Key": "vami.netmask0.PPDM",
                "Value": config["ppdmIpV4Netmask"]
            },
            {
                "Key": "vami.gateway.brs",
                "Value": config["ppdmIpv4Gateway"]
            }
        ]
    else:
        spec["PropertyMapping"] = [
            {
                "Key": "vami.ip0.PPDM",
                "Value": config["ppdmIpV6"]
            },
            {
                "Key": "vami.netmask0.PPDM",
                "Value": config["ppdmIpV6Netmask"]
            },
            {
                "Key": "vami.gateway.brs",
                "Value": config["ppdmIpV6Gateway"]
            }
        ]

    spec["PropertyMapping"].extend([
        {
            "Key": "vami.DNS.brs",
            "Value": ", ".join(config["dnsServers"])
        },
        {
            "Key": "vami.fqdn.brs",
            "Value": config["ppdmFQDN"]
        },
        {
            "Key": "deploymentOption",
            "Value": config["platform"]
        }
    ])

    try:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='ppdm_govc_temp', delete=False
        ) as temp_file:
            json.dump(spec, temp_file, indent=2)
            spec_file = temp_file.name
    except (TypeError, ValueError) as error:
        logger.error("Failed to create govc spec: %s", error)
        raise SystemExit(1) from error

    govc_cmd = (
        f'govc import.ova -options={spec_file} '
        f'-ds={config["ppdmDatastore"]} '
        f'-host={config["esxCluster"]} '
        f'{config["ppdmOVALocation"]}'
    )

    logger.debug("Govc command: %s", govc_cmd)

    return govc_cmd, spec_file


def exec_ova_provisioning(ovf_exec):
    """Executes ovftool deployment command"""
    exit_code = os.system(ovf_exec)

    if exit_code == 0:
        print("-> OVA deployment completed successfully")
        logger.info("OVA deployment completed successfully")
    else:
        print("-> OVA deployment failed")
        logger.error("OVA deployment failed")
        raise SystemExit(1)


def exec_govc_provisioning(govc_exec, spec_file):
    """Executes govc deployment command"""
    try:
        exit_code = os.system(govc_exec)

        if exit_code == 0:
            print("-> OVA deployment completed successfully")
            logger.info("Govc OVA deployment completed successfully")
        else:
            print("-> OVA deployment failed")
            logger.error("Govc OVA deployment failed")
            raise SystemExit(1)
    finally:
        try:
            os.unlink(spec_file)
            logger.debug("Cleaned up temp spec file: %s", spec_file)
        except OSError as e:
            logger.warning("Failed to cleanup temp file %s: %s", spec_file, e)


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
            logger.error("PPDM API check timed out. Exiting")
            raise SystemExit(1)
        if init_rest_call("GET", api_endpoint, None, None, None, True):
            return True
        print("---> PPDM API is unreachable. Retrying")
        logger.info("PPDM API is unreachable. Retrying")
        time.sleep(interval)


def sanitize_payload_for_logging(payload_str, uri):
    """Sanitize sensitive data in payload for logging"""
    if not payload_str:
        return payload_str

    sensitive_endpoints = ["/login", "/licenses", "/smtp"]
    if any(endpoint in uri for endpoint in sensitive_endpoints):
        return "*** REDACTED ***"

    if "configurations" in uri:
        try:
            payload_dict = json.loads(payload_str)
            safe_payload = payload_dict.copy()
            for user in safe_payload.get("osUsers", []):
                if "password" in user:
                    user["password"] = "*** REDACTED ***"
                if "newPassword" in user:
                    user["newPassword"] = "*** REDACTED ***"
            if "applicationUserPassword" in safe_payload:
                safe_payload["applicationUserPassword"] = "*** REDACTED ***"
            for asset in ["dd", "vc", "peerPpdm"]:
                if f"{asset}Password" in safe_payload:
                    safe_payload[f"{asset}Password"] = "*** REDACTED ***"
            return json.dumps(safe_payload)
        except (json.JSONDecodeError, AttributeError):
            return payload_str

    return payload_str


def init_rest_call(verb, uri, token, payload=None, params=None, deploy=None):
    """Generic function for REST calls"""
    code = {200, 201, 202, 204}
    verify = False
    timeout = 90

    if uri.endswith("/login") or deploy:
        headers = {"Content-Type": "application/json"}
    else:
        headers = {"Content-Type": "application/json",
                   "Authorization": f"Bearer {token}"}

    # Log headers safely - mask bearer token if present
    safe_headers = headers.copy()
    if token:
        safe_headers["Authorization"] = "Bearer ***"

    logger.info("REST Call: %s %s", verb, uri)
    logger.info("Headers: %s", safe_headers)

    payload_str = json.dumps(payload)
    logger.info("Payload: %s", sanitize_payload_for_logging(payload_str, uri))

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

    except requests.exceptions.ConnectionError as error:
        if deploy:
            return False
        print(f"->Error Connecting to {uri}: {error}")
        logger.error("Error Connecting to %s: %s", uri, error)
        raise SystemExit(1) from error
    except requests.exceptions.Timeout as error:
        print(f"-> Connection timed out {urllib3}: {error}")
        logger.error("Connection timed out %s: %s", urllib3, error)
        raise SystemExit(1) from error
    except requests.exceptions.RequestException as error:
        if deploy and response.status_code in (401, 502):
            return False
        logger.error("The call %s %s failed with exception: %s",
                     response.request.method, response.url, error)

    logger.info("Response Code: %s", response.status_code)
    logger.debug("Response: %s", response.text)

    if response.status_code not in code:
        raise requests.exceptions.HTTPError(
            f"Failed to query {uri}, code: {response.status_code}, "
            f"body: {response.text}"
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
        logger.error("Cannot query the Data Manager server. Exiting...")
        raise SystemExit("Cannot query the Data Manager server. Exiting...")

    if nodes["content"][0]["status"] != "PENDING":
        logger.error("PPDM is not available for deployment. Exiting...")
        raise SystemExit("PPDM is not available for deployment. Exiting...")

    print("---> PPDM is deployment ready")
    logger.info("PPDM is deployment ready")
    return nodes["content"][0]["id"]


def get_deploy_config(ppdm_uri, token, node_id):
    """Retrieve PPDM deployment configuration"""
    config_uri = f"{ppdm_uri}/configurations"
    desired_config = False

    deploy_config = init_rest_call("GET", config_uri, token)

    if not deploy_config or "content" not in deploy_config:
        logger.error("Cannot query the Data Manager server. Exiting...")
        raise SystemExit("Cannot query the Data Manager server. Exiting...")

    for config_item in deploy_config.get("content"):
        if config_item.get("nodeId") == node_id:
            desired_config = config_item

    if not desired_config:
        print("Could not detect a valid configuration. Exiting.")
        logger.error("Could not detect a valid configuration. Exiting.")
        raise SystemExit(1)

    return desired_config


def accept_eula(eula_type, ppdm_uri, token):
    """Accept PPDM EULAs by type"""
    eula_uri = f"{ppdm_uri}/eulas/{eula_type}"

    payload = {"accepted": True}

    response = init_rest_call("PATCH", eula_uri, token, payload)

    if not response.get("accepted"):
        print(f"{eula_type} EULA could not be accepted, exiting...")
        logger.error("%s EULA could not be accepted, exiting...", eula_type)
        raise SystemExit(1)

    print(f"---> {eula_type} EULA accepted")
    logger.info("%s EULA accepted", eula_type)
    return True


def apply_license(license_file, ppdm_uri, token):
    """Apply PPDM license from file"""
    if license_file.strip().lower() == "trial":
        print("-> Using Trial license")
        logger.info("Using Trial license")
        return True

    try:
        with open(license_file, "r", encoding="utf-8") as file_handle:
            license_content = file_handle.read().strip()
    except (OSError, FileNotFoundError):
        print("-> Could not read license file. Using Trial license")
        logger.warning("Could not read license file. Using Trial license")
        return True

    if not license_content:
        print("-> License file is empty. Using Trial license")
        logger.warning("License file is empty. Using Trial license")
        return True

    license_uri = f"{ppdm_uri}/licenses"
    payload = {"type": "CAPACITY", "key": license_content}

    response = init_rest_call("POST", license_uri, token, payload)

    if response.get("status") == "VALID":
        print("-> Using Capacity license")
        logger.info("Using Capacity license")
        return True

    print("-> License not accepted. Using Trial license")
    logger.warning("License not accepted. Using Trial license")
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
    logger.error("Could not apply SMTP settings. Exiting")
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
            logger.error("Could not apply encryption settings. Exiting")
            raise SystemExit(1)
        for setting in response["properties"]:
            if setting["name"] == "enableProtectionEncryption":
                if config["replicationEncryption"] != bool(setting["value"]):
                    print("Could not apply encryption settings. Exiting")
                    logger.error(
                        "Could not apply encryption settings. Exiting"
                    )
                    raise SystemExit(1)
            elif setting["name"] == "enableReplicationEncryption":
                if config["protectionEncryption"] != bool(setting["value"]):
                    print("Could not apply encryption settings. Exiting")
                    logger.error(
                        "Could not apply encryption settings. Exiting"
                    )
                    raise SystemExit(1)
    except KeyError:
        print("Could not apply encryption settings. Exiting")
        logger.error("Could not apply encryption settings. Exiting")
        raise SystemExit(1) from KeyError

    return True


def get_time_zone(config, ppdm_uri, token):
    """Determine the time zone"""
    local_tz = datetime.datetime.now().astimezone().tzinfo
    local_tz_name = str(local_tz).split(" ", maxsplit=1)[0]

    config["timeZone"] = (
        config.get("timeZone") or config.get("time_zone") or local_tz_name
    )

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
    logger.info("Time zone detected: %s", config['timeZone'])
    return config


def build_deployment_config(config, deploy_config):
    """Form the PPDM deployment config"""
    deploy_config["timeZone"] = config["timeZone"]

    for network in deploy_config["networks"]:
        if "nslookupSuccess" in network:
            if network["nslookupSuccess"]:
                print("-> Name resolution completed successfully")
                logger.info("Name resolution completed successfully")
            else:
                print("-> Warning: name resolution issues")
                logger.warning("Warning: name resolution issues")
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
    logger.info("Deploying configuration %s", deploy_config_id)

    while True:
        if (time.monotonic() - start) > ppdm_deploy_timeout:
            break
        response = init_rest_call("GET", monitor_uri, token)

        if not response:
            if not requires_auth:
                response = init_rest_call(
                    "GET", monitor_uri, token, None, None, True
                )
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
            logger.info(
                "Deployment status %s %s%%", status, percent_complete
            )
            return True
        if status == "ERROR":
            print(f"->Action failed: {json.dumps(response)}")
            logger.error("Action failed: %s", json.dumps(response))
            break
        print(f"---> Deployment status {status} {percent_complete}%")
        logger.info(
            "Deployment status %s %s%%", status, percent_complete
        )
        time.sleep(poll_interval)

    return False


def authenticate(ppdm_uri, username, password):
    """Login to PowerProtect Data Manager"""
    login_uri = f"{ppdm_uri}/login"

    login_payload = {"username": username, "password": password}
    token = init_rest_call("POST", login_uri, None, login_payload)

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
        logger.warning("No certificate response for %s", asset_type.upper())
        return False

    cert = certs[0]
    cert_id = cert.get("id")

    if not cert_id:
        print(f"-> Certificate response missing 'id' for {asset_type.upper()}")
        logger.warning(
            "Certificate response missing 'id' for %s", asset_type.upper()
        )
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

    print(f"Cannot add {asset_type.upper()}. "
          f"Could not accept certificate")
    logger.error(
        f"Cannot add {asset_type.upper()}. Could not accept certificate"
    )
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
        logger.error("AutoSupport could not be configured")
        return False

    properties = response.get("properties")
    if not isinstance(properties, list) or not response.get("id"):
        print("-> AutoSupport could not be configured")
        logger.error("AutoSupport could not be configured")
        return False

    for element in properties:
        if element.get("name") == "transportType":
            element["value"] = "EMAIL"

    response.pop("_links", None)
    payload = response
    response = init_rest_call("PUT", support_uri, token, payload)

    if response.get("id"):
        print("-> AutoSupport configured successfully")
        logger.info("AutoSupport configured successfully")
        return True

    print("-> AutoSupport could not be configured")
    logger.error("AutoSupport could not be configured")
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
        logger.error("Unsupported asset source type: %s", asset_type)
        return False

    creds_id = add_credentials(asset_type, config, ppdm_uri, token)

    if not creds_id:
        print(f"Could not add {asset_type_alt2} credentials")
        logger.error("Could not add %s credentials", asset_type_alt2)
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
        vc_details = {
            "hosting": True,
            "vSphereUiIntegration": config["noVcPlugin"]
        }
        payload["details"] = {"vCenter": vc_details}

    response = init_rest_call("POST", asset_source_id, token, payload)

    if isinstance(response, dict) and response.get("id"):
        print(f"-> {asset_type_alt2} registered successfully")
        logger.info("%s registered successfully", asset_type_alt2)
        details = response.get("details")
        vc = details.get("vCenter") if isinstance(details, dict) else None
        if isinstance(vc, dict):
            if vc.get("hosting"):
                print("--> Hosting vCenter configured successfully")
                logger.info("Hosting vCenter configured successfully")
            if not config["noVcPlugin"] and not vc.get("vSphereUiIntegration"):
                print("--> PPDM vCenter plugin installation was skipped")
                logger.info("PPDM vCenter plugin installation was skipped")
        return True

    print(f"-> {asset_type_alt2} could not be registered")
    logger.error("%s could not be registered", asset_type_alt2)
    return False


def monitor_activity(ppdm_uri, token, activity_id, ppdm_monitor_timeout):
    """Continuously monitor activity by ID"""
    monitor_uri = f"{ppdm_uri}/activities/{activity_id}"
    interval = 5
    start = time.monotonic()

    print(f"---> Monitoring activity ID {activity_id}")
    logger.info("Monitoring activity ID %s", activity_id)

    while True:
        if (time.monotonic() - start) > ppdm_monitor_timeout:
            break
        response = init_rest_call("GET", monitor_uri, token)
        if not response:
            try:
                response = init_rest_call(
                    "GET", monitor_uri, token, None, None, True
                )
            except (SystemExit, requests.exceptions.RequestException):
                time.sleep(30)
                response = init_rest_call(
                    "GET", monitor_uri, token, None, None, True
                )
        state = response.get("state")
        progress = response.get("progress")
        if state == "COMPLETED":
            result = response.get("result")
            if result.get("status") == "FAILED":
                print("---> Activity status FAILED")
                logger.error("Activity status FAILED")
                return False
            print(f"---> Activity status {state} {progress}%")
            logger.info("Activity status %s %s%%", state, progress)
            return True
        if state == "ERROR":
            print(f"->Action failed: {json.dumps(response)}")
            logger.error("Action failed: %s", json.dumps(response))
            break
        print(f"---> Activity status {state} {progress}%")
        logger.info("Activity status %s %s%%", state, progress)
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
            logger.info("Peer PPDM registered successfully")
            return True

    print("---> Peer PPDM could not be registered")
    logger.error("Peer PPDM could not be registered")
    return False


def main():
    # Args assignment
    args = get_args()
    config_file, skip_ova = args.config_file, args.skip_ova
    just_ova, register_vc = args.just_ova, args.register_vc
    no_vc_plugin, add_dd = args.no_vc_plugin, args.add_dd
    connect_peer, ppdm_cross_connect = args.connect_peer, args.cross_connect

    config = read_config(config_file)

    # Initialize logger (includes execution start logging)
    setup_logger(config["logFile"])

    # Const definition
    api_endpoint = "/api/v2"
    ppdm_api_port = 8443
    default_vc_port = 443
    default_dd_port = 3009
    config["ppdmIpTimeout"] = 300
    config["ppdmApiTimeout"] = 1200
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

    # Create the deployment command for PPDM
    if not skip_ova:
        if args.deployment_tool == "ovftool":
            ppdm_ovf_exec = create_ovftool_command(config)
            # Execute PPDM OVA Deployment
            print("-> Provisioning PPDM from OVA")
            logger.info("Provisioning PPDM from OVA")
            exec_ova_provisioning(ppdm_ovf_exec)
        else:
            ppdm_ovf_exec, spec_file = create_govc_command(config)
            # Execute PPDM OVA Deployment
            print("-> Provisioning PPDM from OVA using govc")
            logger.info("Provisioning PPDM from OVA using govc")
            exec_govc_provisioning(ppdm_ovf_exec, spec_file)

    # Break the flow if the justOva parameter is specified
    if just_ova:
        logger.info("Just-ova parameter provided. Exiting")
        print("-> Just-ova parameter provided. Exiting")
        raise SystemExit(0)

    # Check connectivity to PPDM IP and API
    print("-> Checking connectivity to PPDM")
    logger.info("Checking connectivity to PPDM")
    if not check_connectivity(ppdm_ip, config["ppdmIpTimeout"]):
        print(f"---> PPDM IP {ppdm_ip} is unreachable")
        logger.error("PPDM IP %s is unreachable", ppdm_ip)
    else:
        print(f"---> PPDM IP {ppdm_ip} is reachable")
        logger.info("PPDM IP %s is reachable", ppdm_ip)
        print("-> Checking PPDM API readiness")
        logger.info("Checking PPDM API readiness")
        if check_api_accessibility(ppdm_ip, config["ppdmApiTimeout"]):
            print("---> PPDM API is available")
            logger.info("PPDM API is available")

    # Login to the PPDM API
    ppdm_uri = f"https://{ppdm_ip}:{ppdm_api_port}{api_endpoint}"
    token = authenticate(ppdm_uri, username, default_api_pwd)

    # Get PPDM configuration
    print("-> Obtaining PPDM configuration information")
    logger.info("Obtaining PPDM configuration information")
    node_id = check_deployment(ppdm_uri, token)
    deploy_config = get_deploy_config(ppdm_uri, token, node_id)

    # Accept PPDM EULA
    print("-> Accepting PPDM EULA")
    logger.info("Accepting PPDM EULA")
    accept_eula("PPDM", ppdm_uri, token)

    # Apply PPDM License
    print("-> Applying license")
    logger.info("Applying license")
    apply_license(config["license_file"], ppdm_uri, token)

    # Configure SMTP
    if config["smtp"]:
        print("-> Applying SMTP settings")
        logger.info("Applying SMTP settings")
        config_smtp(config, ppdm_uri, token)

    # Apply encryption settings
    print("-> Configuring encryption")
    logger.info("Configuring encryption")
    apply_encryption_settings(config, ppdm_uri, token)

    # Build deployment configuration
    print("-> Building PPDM deployment configuration")
    logger.info("Building PPDM deployment configuration")
    config = get_time_zone(config, ppdm_uri, token)
    deploy_config = build_deployment_config(config, deploy_config)

    # Deploy PPDM
    print("-> Deploying PPDM")
    logger.info("Deploying PPDM")
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
            logger.info("PPDM deployed successfully")
        else:
            print("-> PPDM deployment failed")
            logger.error("PPDM deployment failed")
            raise SystemExit(1)
    else:
        print("-> PPDM deployment failed")
        logger.error("PPDM deployment failed")
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
        logger.info("Initiating post-install tasks")
        token = authenticate(ppdm_uri, username, config["ppdmAdminPwd"])
    if config["autoSupport"]:
        print("-> Accepting TELEMETRY EULA")
        logger.info("Accepting TELEMETRY EULA")
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
            logger.warning(
                "Missing vCenter details, skipping vCenter registration"
            )
    if add_dd:
        config["ddPort"] = config.get("ddPort")
        if not config["ddPort"]:
            config["ddPort"] = default_dd_port
        if config["ddValid"]:
            if accept_certificate("dd", config, ppdm_uri, token):
                register_asset_source("DATADOMAIN", config, ppdm_uri, token)
        else:
            print("-> Missing Data Domain details, skipping DD registration")
            logger.warning(
                "Missing Data Domain details, skipping DD registration"
            )
    if connect_peer:
        config["peerPpdmPort"] = config.get("peerPpdmPort")
        if not config["peerPpdmPort"]:
            config["peerPpdmPort"] = ppdm_api_port
        if config["peerPpdmValid"]:
            if accept_certificate("peerPpdm", config, ppdm_uri, token):
                print("-> Connecting peer PPDM host")
                logger.info("Connecting peer PPDM host")
                qr_enabled = connect_peer_ppdm(config, ppdm_uri, token)
        else:
            print("-> Missing peer PPDM details, skipping configuration")
            logger.warning("Missing peer PPDM details, skipping configuration")
            qr_enabled = False
    else:
        qr_enabled = False
    # Configure bi-directional comm only if there is a peer PPDM
    if qr_enabled and ppdm_cross_connect:
        print("-> Configuring bi-directional replication direction")
        logger.info("Configuring bi-directional replication direction")
        peer_fqdn = config['peerPpdmFQDNorIP']
        peer_ppdm_uri = (
            f"https://{peer_fqdn}:{ppdm_api_port}{api_endpoint}"
        )
        peer_token = authenticate(
            peer_ppdm_uri, config["peerPpdmUser"], config["peerPpdmPassword"]
        )
        peer_config = {"peerPpdmFQDNorIP": config["ppdmFQDN"]}
        peer_config["peerPpdmPort"] = "8443"
        peer_config["peerPpdmUser"] = "admin"
        peer_config["peerPpdmPassword"] = config["ppdmAdminPwd"]
        ppdm_name = "PPDM" + config["ppdmFQDN"].split(".")[0]
        peer_config["peerPpdmNiceName"] = ppdm_name
        if accept_certificate(
            "peerPpdm", peer_config, peer_ppdm_uri, peer_token
        ):
            connect_peer_ppdm(peer_config, peer_ppdm_uri, peer_token)

    print("-> All tasks have been completed")
    logger.info("All tasks have been completed")


if __name__ == "__main__":
    main()
