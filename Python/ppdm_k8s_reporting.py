#!/usr/bin/env python3
"""
Kubernetes Backup Reporting for PowerProtect Data Manager.

Reports backup statistics for protected Kubernetes namespaces
including PVCs and VMs, backup counts, first/last backup times,
and protection capacity.

Author: Idan Kentor <idan.kentor@dell.com>
Copyright: Copyright [2026] [Idan Kentor]

Example usage:
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -p "password" \
      -cl k8s_prod1
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -ns mysql
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -p "password" \
      -cl k8s_prod1 -native
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -native -o json
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -o yaml
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -o json -f report.json
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -o json -f report.json,unprotected.json
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -n
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -e "kube-system,kube-public" -o json
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -pl general-purpose
    python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
      -cl k8s_prod1 -o csv -f report.csv
"""

import argparse
import datetime
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import requests
import urllib3

if "-native" not in sys.argv:
    try:
        from kubernetes import config, dynamic
        from kubernetes.client import api_client
        NATIVE_API = False
    except ImportError:
        NATIVE_API = True
else:
    NATIVE_API = True

urllib3.disable_warnings()
logger = logging.getLogger("ppdm_k8s_reporting")


def get_args():
    """Gets command line args from the user"""
    parser = argparse.ArgumentParser(
        description="K8s Backup & Restore Reporting for PPDM"
    )

    parser.add_argument(
        "-ppdm", "--ppdm",
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
        "-ns", "--namespace",
        dest="ns",
        help="Filter to a specific namespace",
    )

    parser.add_argument(
        "-cl", "--cluster",
        help="K8s cluster API server FQDN or IP",
    )

    parser.add_argument(
        "-pl", "--policy",
        help="Filter to a specific protection policy name",
    )

    parser.add_argument(
        "-native", "--native",
        action="store_true",
        help="Use native kubectl",
    )

    parser.add_argument(
        "-log", "--log-file",
        default="ppdm_k8s_reporting.log",
        help="Log file path (default: ppdm_k8s_reporting.log)",
    )

    parser.add_argument(
        "-f", "--filename",
        help="Export to file(s). Use comma for multiple files "
             "(e.g., report.json,unprotected.json)",
    )

    parser.add_argument(
        "-o", "--output",
        choices=["table", "json", "yaml", "csv"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress stdout output (only export to file if -f is specified)",
    )

    parser.add_argument(
        "-e", "--exclude",
        help="Comma-separated namespaces to exclude from unprotected list",
    )

    parser.add_argument(
        "-n", "--no-unprotected",
        action="store_true",
        help="Suppress unprotected namespaces from output",
    )

    return parser.parse_args()


def setup_logger(log_file):
    """Configure logging to file only"""
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
        logger.info("PPDM K8s Reporting Script Started")
        logger.info(
            "Execution Time: %s",
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        safe_argv = sys.argv.copy()
        for i, arg in enumerate(safe_argv):
            if arg == "-p" and i + 1 < len(safe_argv):
                safe_argv[i + 1] = "*** REDACTED ***"
            elif arg.startswith("--password="):
                safe_argv[i] = "--password=*** REDACTED ***"
        logger.info("Command: %s", " ".join(safe_argv))
        logger.info(separator)
    except (OSError, IOError) as error:
        print(f"-> Could not create log file: {error}")
    return logger


def get_cluster_api():
    """Get k8s cluster API address via Kubernetes module"""
    try:
        client = dynamic.DynamicClient(
            api_client.ApiClient(configuration=config.load_kube_config())
        )
        api_server_url = client.client.configuration.host
        api_server_url = api_server_url.removeprefix("https://")
        api_server_url = api_server_url.replace(":", "/").split("/")[0]
        logger.info("Detected k8s cluster API: %s", api_server_url)
        return api_server_url
    except Exception as error:
        logger.error("Kubernetes module failed to get cluster API: %s", error)
        raise SystemExit("Cannot detect k8s cluster. Exiting...")


def get_cluster_api_native():
    """Get k8s cluster API address via native kubectl commands"""
    command = "kubectl cluster-info"
    with subprocess.Popen(command, shell=True,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as process:
        cluster, error = process.communicate()

    if process.returncode != 0:
        logger.error("kubectl cluster-info failed: %s", error.decode("utf-8"))
        raise SystemExit("Cannot detect k8s cluster. Exiting...")

    if error:
        logger.warning("kubectl cluster-info stderr (non-fatal): %s",
                        error.decode("utf-8"))

    if not cluster:
        logger.error("kubectl cluster-info returned no output")
        raise SystemExit("Cannot detect k8s cluster. Exiting...")

    cluster = cluster.decode("utf-8")
    start = cluster.find("https://")
    if start == -1:
        logger.error("Invalid cluster-info output: %s", cluster)
        raise SystemExit("Cannot parse k8s cluster API. Exiting...")

    start += len("https://")
    api_server_url = cluster[start:].replace(":", "/").split("/")[0]
    logger.info("Detected k8s cluster API: %s", api_server_url)
    return api_server_url


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
    timeout = 90
    code = {200, 201, 202, 204}
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    payload_str = json.dumps(payload) if payload is not None else None

    if uri.endswith("/login"):
        headers = {"Content-Type": "application/json"}
    else:
        if verb.lower() == "get":
            params = params or {}
            params["pageSize"] = 2000
        elif isinstance(payload, dict):
            payload["pageSize"] = 1000
            payload_str = json.dumps(payload)

    logger.info(
        "REST Call: %s %s, Params: %s, Payload: %s", verb, uri,
        params, sanitize_payload_for_logging(payload_str, uri)
    )

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
            if response.status_code == 401:
                message = f"Authentication failed (401): check username/password for {uri}"
            else:
                message = f"Bad gateway (502) from {uri}"
            print(f"-> {message}")
            logger.error(
                "REST call failed: %s %s - %s", verb, uri, message
            )
            return False

        print(
            f"-> The call {response.request.method} {response.url} "
            f"failed with exception: {error}"
        )
        logger.error(
            "REST call failed: %s %s - Status %d - Exception: %s",
            response.request.method, response.url,
            response.status_code, error
        )
        return False

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


def match_cluster_inventory_source(uri, token, cluster, k8s_cluster=None):
    """Match the provided and actual k8s cluster names with the detected one"""
    uri = f"{uri}/inventory-sources"
    query = 'type eq "KUBERNETES"'
    query_params = {'filter': query}

    response = init_rest_call("GET", uri, token, None, query_params)
    content = response.get("content") if isinstance(response, dict) else []

    if len(content) == 1:
        return content[0]["id"]

    matches = []
    for reg_cluster in content:
        name = (reg_cluster.get("name") or "").lower()
        address = (reg_cluster.get("address") or "").lower()
        cl = (cluster or "").lower()
        k8s = (k8s_cluster or "").lower()

        match_value = cl or k8s
        if match_value and (match_value in name or match_value == address):
            matches.append(reg_cluster)

    if len(matches) == 1:
        return matches[0]["id"]

    if len(matches) > 1:
        print("Multiple clusters matched. Use exact cluster name with -cl")
        logger.error("Ambiguous cluster match: %d clusters matched", len(matches))
        raise SystemExit(1)

    print("No matching cluster found. Check -cl argument")
    logger.error("No cluster match found for cluster=%s, k8s_cluster=%s", cluster, k8s_cluster)
    raise SystemExit(1)


def get_all_content(uri, token, query_params, response):
    """Collect all content from an API response, fetching extra pages if needed"""
    total_pages = response.get("page", {}).get("totalPages", 1)
    content = response.get("content", [])

    for page in range(2, total_pages + 1):
        params = query_params.copy()
        params["page"] = page
        next_resp = init_rest_call("GET", uri, token, None, params)
        if isinstance(next_resp, dict):
            content.extend(next_resp.get("content", []))

    return content


def get_assets_per_k8s_cluster(uri, token, cluster_id, ns=None):
    """Get namespace assets per k8s cluster through PPDM"""
    endpoint = f"{uri}/assets"
    query = ('type eq "KUBERNETES_NAMESPACE" and '
             'protectionStatus eq "PROTECTED"')
    cluster_query = f'{query} and inventorySourceRefs.id eq "{cluster_id}"'

    if ns:
        cluster_query = f'{cluster_query} and name eq "{ns}"'
    query_params = {'filter': cluster_query}

    response = init_rest_call("GET", endpoint, token, None, query_params)
    content = response.get("content") if isinstance(response, dict) else None
    if not content:
        raise SystemExit("Cannot detect k8s namespace assets. Exiting...")

    content = get_all_content(endpoint, token, query_params, response)
    asset_names = [asset["name"] for asset in content]
    return asset_names, content


def get_namespaces(ns=None):
    """Get all configured k8s namespaces with the Kubernetes module"""
    config.load_kube_config()
    client = dynamic.DynamicClient(api_client.ApiClient())
    api = client.resources.get(api_version="v1", kind="Namespace")

    if ns:
        namespaces = api.get(name=ns)
        return [namespaces.metadata.name] if namespaces else []

    namespaces = api.get()
    return [item.metadata.name for item in namespaces.items]


def get_namespaces_native(ns=None):
    """Get all configured k8s namespaces natively using kubectl"""
    if ns:
        command = f"kubectl get ns {ns} -o jsonpath='{{.metadata.name}}'"
    else:
        command = "kubectl get ns -o jsonpath='{.items[*].metadata.name}'"

    with subprocess.Popen(command, shell=True,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as process:
        namespaces, error = process.communicate()

    if process.returncode != 0 or not namespaces:
        if error:
            logger.error("kubectl get ns failed: %s", error.decode("utf-8"))
        raise SystemExit("No k8s namespaces detected. Exiting...")

    if error:
        logger.warning("kubectl get ns stderr (non-fatal): %s",
                        error.decode("utf-8"))

    return namespaces.decode("utf-8").split()


def compute_namespaces(ppdm_namespaces, cluster_namespaces):
    """Compute the available namespaces which are protected in PPDM"""
    protected = set(ppdm_namespaces) & set(cluster_namespaces)
    unprotected = set(cluster_namespaces) - set(ppdm_namespaces)

    if unprotected:
        logger.info("Displaying %d unprotected namespaces",
                    len(unprotected))

    return sorted(protected), sorted(unprotected)


def get_storage_class_mapping(uri, token, cluster_id):
    """Get PVC name to storage class mapping for all namespaces in cluster via v2 API"""
    uri = f"{uri}/assets"
    pvc_filter = (
        'subtype eq "K8S_PERSISTENT_VOLUME_CLAIM" and '
        f'inventorySourceRefs.id eq "{cluster_id}"'
    )
    query_params = {"filter": pvc_filter}

    response = init_rest_call("GET", uri, token, None, query_params)
    content = response.get("content") if isinstance(response, dict) else None

    if not content:
        return {}

    content = get_all_content(uri, token, query_params, response)

    namespace_maps = {}
    for pvc_asset in content:
        pvc_details = pvc_asset.get("details", {}).get("k8s", {})
        namespace = pvc_details.get("namespace")
        pvc_claim = pvc_details.get("persistentVolumeClaim", {})
        storage_class = pvc_claim.get("storageClassName")
        if namespace and storage_class:
            if namespace not in namespace_maps:
                namespace_maps[namespace] = {}
            namespace_maps[namespace][pvc_asset.get("name")] = storage_class

    return namespace_maps


def get_backup_copies(uri, token, asset_id, storage_class_map=None):
    """Get backup copy stats for a given PPDM asset"""
    storage_class_map = storage_class_map or {}
    uri = f"{uri}/copies-search"

    asset_filter = f'assetRef.id eq "{asset_id}"'
    location_filter = 'location in ("LOCAL", "LOCAL_RECALLED")'
    replica_filter = "replica eq false"
    state_filter = 'not state in ("DELETED", "DELETING", "UNAVAILABLE")'
    copy_filter = (
        f"{asset_filter} and {location_filter} "
        f"and {replica_filter} and {state_filter}"
    )

    default_stats = {
        "count": 0,
        "first": None,
        "last": None,
        "vm_count": 0,
        "pvc_count": "0/0",
        "storage_classes": []
    }

    payload = {
        "filter": copy_filter,
        "orderby": "backupTime ASC",
    }

    response = init_rest_call("POST", uri, token, payload)
    copies = response.get("content") if isinstance(response, dict) else None
    if not copies:
        return default_stats

    latest_copy = copies[-1]
    extended_data = latest_copy.get("extendedData", {})
    vm_count = len(extended_data.get("k8sVirtualMachines", []))

    all_pvcs = extended_data.get("persistentVolumeClaims", [])
    total_pvcs = len(all_pvcs)
    included_pvcs = 0
    storage_classes = []

    for pvc in all_pvcs:
        if not pvc.get("excluded", True):
            included_pvcs += 1
        storage_class = storage_class_map.get(pvc.get("name"))
        if storage_class and storage_class not in storage_classes:
            storage_classes.append(storage_class)

    if total_pvcs > 0:
        pvc_count = f"{included_pvcs}/{total_pvcs}"
    else:
        pvc_count = "0/0"

    return {
        "count": len(copies),
        "first": format_timestamp(copies[0].get("backupTime")),
        "last": format_timestamp(latest_copy.get("backupTime")),
        "vm_count": vm_count,
        "pvc_count": pvc_count,
        "storage_classes": storage_classes
    }


def format_timestamp(timestamp):
    """Formats a PPDM timestamp to a readable format"""
    if not timestamp:
        return None

    try:
        dt = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        try:
            dt = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return timestamp

    return dt.strftime("%m/%d/%y %I:%M:%S %p UTC")


def build_asset_report(asset, backup_stats):
    """Builds a report dict for a single PPDM asset"""
    size_bytes = asset.get("protectionCapacity", {}).get("size")
    if size_bytes:
        size_gb = size_bytes / (1024**3)
        if size_gb >= 1.0:
            size_display = f"{size_gb:.2f} GB"
        else:
            size_display = f"{size_bytes / (1024**2):.2f} MB"
    else:
        size_display = "N/A"

    policy = asset.get("protectionPolicyRef")
    if policy:
        policy_name = policy.get("name") or "N/A"
    else:
        policy_name = "N/A"

    storage_classes = backup_stats.get("storage_classes", [])
    sc_display = ", ".join(storage_classes) if storage_classes else "N/A"

    return {
        "Namespace": asset.get("name"),
        "Policy": policy_name,
        "Copies": backup_stats.get("count", 0),
        "VMs": backup_stats.get("vm_count", 0),
        "PVCs": backup_stats.get("pvc_count", 0),
        "Storage Classes": sc_display,
        "First Backup": backup_stats.get("first", "N/A"),
        "Last Backup": backup_stats.get("last", "N/A"),
        "Size": size_display,
    }


def format_report(report, unprotected, format_type):
    """Format report in specified format"""
    if format_type == "table":
        return format_table(report, unprotected)

    if format_type == "json":
        json_report = []
        for item in report:
            sc_str = item["Storage Classes"]
            sc_list = sc_str.split(", ") if sc_str != "N/A" else []
            json_report.append({
                "namespace": item["Namespace"],
                "policy": item["Policy"],
                "copies": item["Copies"],
                "vms": item["VMs"],
                "pvcs": item["PVCs"],
                "storage_classes": sc_list,
                "first_backup": item["First Backup"],
                "last_backup": item["Last Backup"],
                "size": item["Size"]
            })
        result = {
            "protected_count": len(json_report),
            "unprotected_count": len(unprotected),
            "protected_namespaces": json_report
        }
        if unprotected:
            result["unprotected_namespaces"] = sorted(unprotected)
        return json.dumps(result, indent=2)

    if format_type == "yaml":
        yaml_lines = [
            f"protected_count: {len(report)}",
            f"unprotected_count: {len(unprotected)}",
            "protected_namespaces:",
        ]
        for item in report:
            sc_str = item['Storage Classes']
            sc_list = sc_str.split(", ") if sc_str != "N/A" else []
            yaml_lines.append(f"  - namespace: {item['Namespace']}")
            yaml_lines.append(f"    policy: {item['Policy']}")
            yaml_lines.append(f"    copies: {item['Copies']}")
            yaml_lines.append(f"    vms: {item['VMs']}")
            yaml_lines.append(f"    pvcs: {item['PVCs']}")
            yaml_lines.append(f"    storage_classes: {sc_list}")
            yaml_lines.append(f"    first_backup: {item['First Backup']}")
            yaml_lines.append(f"    last_backup: {item['Last Backup']}")
            yaml_lines.append(f"    size: {item['Size']}")
        if unprotected:
            yaml_lines.append("unprotected_namespaces:")
            for ns in unprotected:
                yaml_lines.append(f"  - {ns}")
        return "\n".join(yaml_lines) + "\n"

    if format_type == "csv":
        headers = list(report[0].keys()) if report else []
        lines = [",".join(headers)]
        for item in report:
            values = []
            for h in headers:
                val = str(item[h])
                if "," in val:
                    val = f'"{val}"'
                values.append(val)
            lines.append(",".join(values))
        return "\n".join(lines) + "\n"


def format_table(report, unprotected):
    """Format report as table string"""
    if not report and not unprotected:
        return "No data to display\n"

    lines = []
    if report:
        headers = list(report[0].keys())
        col_widths = {}
        for header in headers:
            col_widths[header] = len(header)
        for row in report:
            for header in headers:
                value_len = len(str(row.get(header, "")))
                col_widths[header] = max(col_widths[header], value_len)
        header_parts = []
        separator_parts = []
        for header in headers:
            header_parts.append(header.ljust(col_widths[header]))
            separator_parts.append("-" * col_widths[header])
        lines.append("  ".join(header_parts))
        lines.append("  ".join(separator_parts))
        for row in report:
            row_parts = []
            for header in headers:
                value = str(row.get(header, ""))
                row_parts.append(value.ljust(col_widths[header]))
            lines.append("  ".join(row_parts))

    if unprotected:
        if report:
            lines.append("")
        lines.append(f"-> Unprotected namespaces: {len(unprotected)}")

        for namespace in unprotected:
            lines.append(f"  {namespace}")
        lines.append("")

    elif report:
        lines.append("")

    return "\n".join(lines) + "\n"


def export_report(report, unprotected, file_names, format_type):
    """Export report to file(s) in specified format"""
    files = file_names.split(",")

    if len(files) > 2:
        logger.warning("More than 2 files specified. Using first 2 only.")
        print("-> Warning: More than 2 files specified. Using first 2 only.")
        files = files[:2]

    protected_file = files[0].strip()
    protected_content = format_report(report, [], format_type)

    with open(protected_file, 'w') as file:
        file.write(protected_content)

    print(f"-> Protected namespaces exported to {protected_file}")
    logger.info("Protected namespaces exported to %s", protected_file)

    if len(files) == 2:
        unprotected_file = files[1].strip()
        if format_type == "json":
            unprotected_content = json.dumps(sorted(unprotected), indent=2)
        elif format_type == "yaml":
            yaml_lines = ["unprotected_namespaces:"]
            for ns in sorted(unprotected):
                yaml_lines.append(f"  - {ns}")
            unprotected_content = "\n".join(yaml_lines) + "\n"
        elif format_type == "csv":
            csv_lines = ["unprotected_namespace"]
            for ns in sorted(unprotected):
                csv_lines.append(ns)
            unprotected_content = "\n".join(csv_lines) + "\n"
        else:
            unprotected_content = "\n".join(sorted(unprotected)) + "\n"
        with open(unprotected_file, 'w') as file:
            file.write(unprotected_content)
        print(f"-> Unprotected namespaces exported to {unprotected_file}")
        logger.info("Unprotected namespaces exported to %s", unprotected_file)


def authenticate(uri, username, password):
    """Login"""
    uri = f"{uri}/login"

    payload = {"username": username, "password": password}
    logger.info("Attempting login to PPDM API")

    token = init_rest_call("POST", uri, None, payload)

    if token:
        logger.info("Login successful")
    else:
        logger.error("Login failed")

    return token


def main():
    # Args assignment
    args = get_args()
    ppdm, username = args.ppdm, args.username
    ns, cluster = args.ns, args.cluster

    # Initialize logger
    setup_logger(args.log_file)

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

    # Native mode
    native = args.native or NATIVE_API

    # Const definition
    api_endpoint = "/api/v2"
    api_v3_endpoint = "/api/v3"
    api_port = 8443

    # Logs into the PPDM API
    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    uri_v3 = f"https://{ppdm}:{api_port}{api_v3_endpoint}"
    token = authenticate(uri, username, password)
    if not token:
        print("-> Login failed")
        raise SystemExit(1)

    # Detect k8s cluster
    logger.info("Detecting k8s cluster")

    if native:
        k8s_cluster = get_cluster_api_native()
    else:
        k8s_cluster = get_cluster_api()
    cluster_id = match_cluster_inventory_source(
        uri, token, cluster, k8s_cluster
    )
    logger.info("Matched cluster ID: %s", cluster_id)

    asset_names, assets = get_assets_per_k8s_cluster(
        uri_v3, token, cluster_id, ns
    )
    logger.info("Found %d protected namespace assets", len(assets))

    # Filter by policy name if specified
    if args.policy:
        filtered = []
        for asset in assets:
            policy = asset.get("protectionPolicyRef")
            if policy and policy.get("name") == args.policy:
                filtered.append(asset)
        if not filtered:
            print(f"-> No assets found for policy '{args.policy}'")
            raise SystemExit(1)
        assets = filtered
        asset_names = [asset["name"] for asset in assets]
        logger.info("Filtered to policy '%s': %d assets",
                    args.policy, len(assets))

    # Compare with running namespaces
    if native:
        running_namespaces = get_namespaces_native(ns)
    else:
        running_namespaces = get_namespaces(ns)
    protected, unprotected = compute_namespaces(
        asset_names, running_namespaces
    )

    default_excluded_namespaces = {
        "kube-system", "kube-public", "kube-node-lease",
        "cattle-system", "cattle-fleet-system",
        "cattle-fleet-clusters-system", "cattle-fleet-local-system",
        "cattle-provisioning-capi-system", "cattle-ui-plugin-system",
        "cattle-dashboards", "harvester-system", "harvester-public",
        "longhorn-system", "fleet-local", "fleet-default", "local",
        "velero-ppdm", "powerprotect", "csi-powerstore", "isilon",
        "csi-powermax", "vmware-system-csi"
    }

    # Handle conflict between --exclude and --no-unprotected
    if args.no_unprotected and args.exclude:
        print("-> Warning: --no-unprotected overrides --exclude")
        logger.warning("--no-unprotected overrides --exclude")
        args.exclude = None

    exclusions = default_excluded_namespaces.copy()

    if args.exclude:
        user_exclusions = {item.strip() for item in args.exclude.split(",")}
        exclusions.update(user_exclusions)
        logger.info("User exclusions: %s", user_exclusions)

    original_count = len(unprotected)
    unprotected = list(set(unprotected) - exclusions)
    filtered_count = original_count - len(unprotected)

    if filtered_count > 0:
        logger.info("Filtered out %d namespaces", filtered_count)

    # Suppress unprotected if requested or filtering by policy
    if args.no_unprotected or args.policy:
        unprotected = []

    logger.info("Found %d protected namespaces", len(assets))
    if args.output == "table":
        print(f"-> Protected namespaces: {len(assets)}")
        if args.quiet and unprotected:
            print(f"-> Unprotected namespaces: {len(unprotected)}")

    # Build report
    storage_class_mapping = get_storage_class_mapping(uri, token, cluster_id)
    report = []
    for asset in assets:
        storage_class_map = storage_class_mapping.get(asset["name"], {})
        backup_stats = get_backup_copies(
            uri_v3, token, asset["id"], storage_class_map
        )
        report.append(build_asset_report(asset, backup_stats))
    if ns:
        unprotected = []

    content = format_report(report, unprotected, args.output)

    if unprotected:
        logger.info("Found %d unprotected namespaces", len(unprotected))

    # Print to stdout unless quiet mode
    if not args.quiet:
        print(content, end='')
        logger.info("Report displayed in %s format", args.output)

    # Export to file(s) if specified
    if args.filename:
        export_report(report, unprotected, args.filename, args.output)
    logger.info("Report completed: %d namespaces", len(report))


if __name__ == "__main__":
    main()
