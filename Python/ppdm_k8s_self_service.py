#!/usr/bin/env python3

"""
PowerProtect Data Manager Kubernetes Self-Service Script.

Provides ad-hoc backup and restore for Kubernetes namespaces
through Dell PowerProtect Data Manager REST API.

Author: Idan Kentor <idan.kentor@dell.com>
Copyright: [2026] [Idan Kentor]

Examples:
    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a list -ns myns

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a list -ns myns -o json

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a backup -ns myns -ret "7 days"

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a restore -ns myns -rt rto

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a restore -ns myns -rt rtn \
        -cl mycluster

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a restore -ns myns -rt rtn \
        -cl mycluster -target-ns myns-restore

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a restore -ns myns -rt rtn \
        -alt-cluster upstream_cl1

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a restore -ns myns -rt rtn \
        -skip-metadata

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a restore -ns myns -rt rtn \
        -skip-pvcs

    python ppdm_k8s_self_service.py -ppdm 10.0.0.1 \
        -p pass -a monitor -activity_id <uuid>
"""

import argparse
import json
import logging
import logging.handlers
import os
import time
from datetime import datetime
import requests
import urllib3

urllib3.disable_warnings()

logger = logging.getLogger("ppdm_k8s_self_service")


def setup_logger(log_file):
    """Configure logging to file only"""
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - "
            "%(funcName)s:%(lineno)d - %(message)s"
        ))
        logger.addHandler(file_handler)
        separator = "=" * 80
        logger.info(separator)
        logger.info("PPDM K8s Self-Service Script Started")
        logger.info(
            "Execution Time: %s",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        logger.info(separator)
    except (OSError, IOError) as error:
        print(f"-> Could not create log file: {error}")


def get_args():
    """Get command line arguments"""
    parser = argparse.ArgumentParser(
        description="PPDM Kubernetes Self-Service"
    )

    parser.add_argument(
        "-ppdm", "--ppdm",
        required=True,
        help="PPDM server FQDN or IP"
    )

    parser.add_argument(
        "-u", "--username", default="admin",
        help="PPDM username (default: admin)"
    )

    parser.add_argument(
        "-p", "--password",
        help="PPDM password"
    )

    parser.add_argument(
        "-envpassword", action="store_true",
        help="Read password from PPDM_PASSWORD env var"
    )

    parser.add_argument(
        "-a", "--action", required=True,
        choices=["list", "backup", "restore",
                 "monitor", "discovery"],
        help="Action to perform"
    )

    parser.add_argument(
        "-ns", "--namespace",
        help="Kubernetes namespace"
    )

    parser.add_argument(
        "-cl", "--cluster",
        help="Kubernetes Cluster name (case-insensitive)"
    )

    parser.add_argument(
        "-ret", "--retention",
        help="Retention (e.g., '7 days', '2 weeks')"
    )

    parser.add_argument(
        "-full", action="store_true",
        help="Force full backup"
    )

    parser.add_argument(
        "-rt", "--restore-type",
        choices=["rto", "rte", "rtn"],
        help=(
            "Restore type: "
            "rto=restore to original namespace, "
            "rte=restore to existing namespace, "
            "rtn=restore to new namespace. "
            "Use -alt-cluster for cross-cluster restores "
            "(rte/rtn only)"
        )
    )

    parser.add_argument(
        "-copy-id", "--copy-id",
        help="Specific backup copy ID"
    )

    parser.add_argument(
        "-timestamp",
        help="Restore by timestamp (YYYY-MM-DD [HH:MM:SS])"
    )

    parser.add_argument(
        "-timeframe",
        help="Filter copies by age: '<N> hours|days|weeks'"
    )

    parser.add_argument(
        "-target-ns", "--target-ns",
        help="Target namespace for rtn/rte restore"
    )

    parser.add_argument(
        "-alt-cluster",
        help="Alternate cluster name for restore "
             "(case-insensitive)"
    )

    parser.add_argument(
        "-cluster-id", "--cluster-id",
        help="Target cluster ID for cross-cluster restore"
    )

    parser.add_argument(
        "-include-cluster", "--include-cluster-resources",
        action="store_true",
        help="Include cluster-scoped resources"
    )

    parser.add_argument(
        "-no-overwrite-pvc", action="store_true",
        help="Do not overwrite existing PVCs"
    )

    parser.add_argument(
        "-exclude-k8s-vm", action="append", default=[],
        help="Exclude specific K8s VM (repeatable)"
    )

    parser.add_argument(
        "-power-on-vm", action="store_true",
        help="Power on VMs after restore (default: off)"
    )

    parser.add_argument(
        "-restore-bios-uuid", action="store_true",
        help="Restore BIOS UUID (default: off)"
    )

    parser.add_argument(
        "-skip-metadata", action="store_true",
        help="Restore PVCs only, skip namespace metadata and VMs"
    )

    parser.add_argument(
        "-skip-pvcs", action="store_true",
        help="Restore namespace metadata only, skip PVCs"
    )

    parser.add_argument(
        "-storage-class",
        help="Target storage class for restore"
    )

    parser.add_argument(
        "-nmonitor", action="store_true",
        help="Do not monitor activity after starting"
    )

    parser.add_argument(
        "-activity_id",
        help="Activity ID to monitor"
    )

    parser.add_argument(
        "-aidfile",
        help="File containing activity ID"
    )

    parser.add_argument(
        "-outfile",
        help="File to save activity ID"
    )

    parser.add_argument(
        "-o", "--output",
        choices=["text", "json", "yaml"],
        default="text",
        help="Output format for list action (default: text)"
    )

    parser.add_argument(
        "-log", "--log-file",
        default="ppdm_k8s_self_service.log",
        help="Log file path"
    )

    return parser.parse_args()


def sanitize_payload(payload_str, uri):
    """Truncate payload to 300 chars, redact login"""
    if uri.endswith("/login") and payload_str:
        return "*** REDACTED ***"
    if not payload_str:
        return payload_str
    preview = payload_str[:300].rstrip()
    if len(payload_str) >= 300:
        preview += "..."
    return preview


def log_response(verb, uri, response):
    """Log response body summary (300 chars)"""
    try:
        content = response.text
        preview = content[:300].rstrip()
        if len(content) >= 300:
            preview += "..."
        logger.info(
            "%s %s: %d bytes - %s",
            verb, uri, len(response.content), preview
        )
    except Exception:
        logger.info(
            "%s %s: %d bytes (non-text)",
            verb, uri, len(response.content)
        )


def init_rest_call(verb, uri, token, payload=None,
                   params=None):
    """Generic REST call handler"""
    code = {200, 201, 202, 204}
    headers = {"Content-Type": "application/json"}

    if not uri.endswith("/login") and token:
        headers["Authorization"] = f"Bearer {token}"

    payload_str = (
        json.dumps(payload) if payload is not None else None
    )

    logger.info(
        "REST Call: %s %s, Params: %s, Payload: %s",
        verb, uri, params,
        sanitize_payload(payload_str, uri)
    )

    response = None

    try:
        response = requests.request(
            verb, uri,
            headers=headers,
            params=params,
            data=payload_str,
            verify=False,
            timeout=90,
        )
        response.raise_for_status()
    except requests.exceptions.ConnectionError as err:
        logger.error("Connection error: %s - %s", uri, err)
        print(f"-> Error connecting to {uri}")
        return False
    except requests.exceptions.Timeout as err:
        logger.error("Timeout: %s - %s", uri, err)
        print(f"-> Connection timed out: {uri}")
        return False
    except requests.exceptions.RequestException as err:
        if not response:
            logger.error("No response: %s %s - %s",
                         verb, uri, err)
            return False
        if response.status_code in (401, 502):
            logger.error("REST failed: %s %s - %d",
                         verb, uri, response.status_code)
            return False
        logger.error("REST failed: %s %s - %d - %s",
                     verb, uri, response.status_code, err)
        return False

    if response.status_code not in code:
        raise requests.exceptions.HTTPError(
            f"Failed: {uri}, code: {response.status_code}, "
            f"body: {response.text}"
        )

    logger.info(
        "REST OK: %s %s, %d, %.3fs",
        verb, uri, response.status_code,
        response.elapsed.total_seconds()
    )

    if not response.content:
        return True

    log_response(verb, uri, response)

    if uri.endswith("/login"):
        return response.json()["access_token"]

    try:
        return response.json()
    except ValueError:
        return response.content


def authenticate(server, user, password):
    """Login to PPDM"""
    uri = f"https://{server}:8443/api/v2/login"

    token = init_rest_call(
        "POST", uri, None,
        {"username": user, "password": password}
    )

    if token:
        logger.info("Login successful")
    else:
        logger.error("Login failed")
        print("-> Authentication failed")

    return token


def check_version(version_str):
    """Check if PPDM version >= 19.16 (v3 API)"""
    try:
        parts = str(version_str).split(".")
        major = int(parts[0])
        minor = int(parts[1].split("-")[0])
    except (ValueError, IndexError, AttributeError):
        return False

    return (major > 19) or (major == 19 and minor >= 16)


def get_api_base(server, token):
    """Determine API base URI from PPDM version (v3 only)"""
    uri = f"https://{server}:8443/api/v2"

    response = init_rest_call("GET", f"{uri}/nodes", token)

    if not response or not response.get("content"):
        raise SystemExit(
            "Error: Cannot determine PPDM version"
        )

    version = response["content"][0].get("version")

    if not check_version(version):
        raise SystemExit(
            f"Error: PPDM version {version} < 19.16 "
            "(v3 API required)"
        )

    return f"https://{server}:8443/api/v3"


def get_namespace_asset(uri, token, namespace, cluster=None):
    """Get namespace asset ID, protection policy, and cluster info"""
    query = (
        'type eq "KUBERNETES_NAMESPACE" and '
        f'name eq "{namespace}"'
    )
    if cluster:
        query += f' and inventorySourceRef.name eq "{cluster}"'

    endpoint = f"{uri}/assets"
    params = {"filter": query}

    response = init_rest_call("GET", endpoint, token, params=params)

    if not response or not response.get("content"):
        raise SystemExit(
            f"Namespace not found: {namespace}"
            + (f" on cluster '{cluster}'" if cluster else "")
        )

    content = response["content"]

    if len(content) > 1 and not cluster:
        names = []
        for a in content:
            names.append(a.get("inventorySourceRef", {}).get("name", "?"))
        msg = (
            f"Namespace '{namespace}' found on multiple clusters: "
            f"{', '.join(names)}. Use -cl <cluster-name> to specify."
        )
        logger.error(msg)
        raise SystemExit(msg)

    asset = content[0]
    cluster_info = {}
    inventory_source = asset.get("inventorySourceRef", {})

    if inventory_source.get("id"):
        cluster_info = {
            "id": inventory_source.get("id", ""),
            "name": inventory_source.get("name", "Unknown")
        }

    return (
        asset["id"],
        asset.get("protectionPolicyRef", {}),
        cluster_info
    )


def format_output(data, fmt):
    """Format and print data as text, json, or yaml"""
    if fmt == "json":
        print(json.dumps(data, indent=2))
        return

    if fmt == "yaml":
        lines = []
        for key, value in data.items():
            if isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for k, v in item.items():
                            prefix = "  - " if first else "    "
                            lines.append(f"{prefix}{k}: {v}")
                            first = False
                    else:
                        lines.append(f"  - {item}")
            else:
                lines.append(f"{key}: {value}")
        print("\n".join(lines))
        return

    title_map = {
        "pvcs_in_latest_copy": "PVCs in latest copy",
        "vms_in_latest_copy": "VMs in latest copy"
    }
    
    label_map = {
        "size_gb": "Size GB",
        "storage_class": "Storage Class"
    }

    for key, value in data.items():
        if isinstance(value, list):
            if not value:
                continue
            
            display_title = title_map.get(key, key.replace("_", " ").title())
            print(f"\n{display_title}:")
            print("-" * 60)
            print()
            
            if value and isinstance(value[0], dict):
                headers = list(value[0].keys())
                header_labels = []
                for h in headers:
                    if h in label_map:
                        header_labels.append(label_map[h])
                    else:
                        header_labels.append(h.replace("_", " ").title())
                
                col_widths = []
                for i, label in enumerate(header_labels):
                    max_width = len(label)
                    for item in value:
                        val_str = str(list(item.values())[i])
                        max_width = max(max_width, len(val_str))
                    col_widths.append(max_width)
                
                header_parts = []
                for i, label in enumerate(header_labels):
                    header_parts.append(label.ljust(col_widths[i]))
                print(f"  {' '.join(header_parts)}")
                
                for item in value:
                    row_parts = []
                    for i, val in enumerate(item.values()):
                        row_parts.append(str(val).ljust(col_widths[i]))
                    print(f"  {' '.join(row_parts)}")
                print()
            else:
                for item in value:
                    print(f"  {item}")
                print()
        else:
            print(f"{key}: {value}")


def namespace_exists(uri, token, namespace):
    """Check if a namespace is known to PPDM (discovered from K8s)"""
    query = (
        'type eq "KUBERNETES_NAMESPACE" and '
        f'name eq "{namespace}"'
    )
    endpoint = f"{uri}/assets"
    params = {"filter": query}

    response = init_rest_call("GET", endpoint, token, params=params)

    if response and response.get("content"):
        return True

    return False


def get_cluster_id(uri, token, cluster_name):
    """Resolve K8s cluster name to inventory source ID"""
    endpoint = f"{uri}/inventory-sources"
    params = {"filter": 'type eq "KUBERNETES_CLUSTER"'}

    response = init_rest_call(
        "GET", endpoint, token, params=params
    )

    if not response or not response.get("content"):
        return None

    for cluster in response["content"]:
        if cluster.get("name", "").lower() == cluster_name.lower():
            return cluster["id"]

    return None


def validate_cluster_id(uri, token, cluster_id):
    """Validate that cluster ID exists in inventory sources"""
    endpoint = f"{uri}/inventory-sources/{cluster_id}"
    response = init_rest_call("GET", endpoint, token)
    return bool(response)


def get_storage_classes(uri, token, cluster_id, copy_id):
    """Get available storage classes for PVCs in a copy"""
    endpoint = (
        f"{uri}/kubernetes-clusters/{cluster_id}"
        f"/pvc-storage-class-mappings"
    )
    params = {"copyId": copy_id}

    response = init_rest_call("GET", endpoint, token, params=params)

    if not response:
        return {}

    result = {}

    for entry in response.get("content", []):
        pvc_name = entry.get("pvcName")
        classes = entry.get("storageClasses", [])
        if pvc_name and classes:
            result[pvc_name] = classes

    return result


def parse_timeframe(timeframe):
    """Parse '<N> hours|days|weeks' into seconds"""
    multipliers = {
        "hours": 3600, "days": 86400, "weeks": 604800
    }

    parts = timeframe.strip().lower().split()

    if len(parts) == 2 and parts[0].isdigit():
        unit = parts[1].rstrip("s") + "s"
        if unit in multipliers:
            return int(parts[0]) * multipliers[unit]

    raise SystemExit(
        "Error: timeframe format is '<N> hours|days|weeks'"
    )


def get_copies(uri, token, asset_id, timeframe=None):
    """Get available backup copies for an asset via copies-search"""
    endpoint = f"{uri}/copies-search"
    query = (
        f'assetRef.id eq "{asset_id}"'
        ' and location in ("LOCAL", "LOCAL_RECALLED")'
        ' and replica eq false'
        ' and not state in'
        ' ("DELETED", "DELETING", "UNAVAILABLE")'
    )

    if timeframe:
        cutoff = time.time() - parse_timeframe(timeframe)
        cutoff_str = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(cutoff)
        )
        query += f' and backupTime ge "{cutoff_str}"'

    payload = {
        "filter": query,
        "orderby": "backupTime DESC"
    }

    response = init_rest_call("POST", endpoint, token, payload)

    if not response or not response.get("content"):
        return []

    copies = response["content"]

    for copy in copies:
        logger.info(
            "Copy %s: state=%s location=%s backupTime=%s",
            copy.get("id", "?")[:8],
            copy.get("state"),
            copy.get("location"),
            copy.get("backupTime", "")
        )

    return copies


def get_backup_stage_id(uri, token, policy_id):
    """Get backup objective ID from a protection policy"""
    endpoint = f"{uri}/protection-policies/{policy_id}"

    response = init_rest_call("GET", endpoint, token)

    if not response:
        raise SystemExit("Could not retrieve policy")

    for obj in response.get("objectives", []):
        if obj.get("type") == "BACKUP":
            return obj.get("id")

    raise SystemExit("No backup stage found in policy")


def build_retention(retention_str):
    """Build v3 retention JSON from string like '7 days'"""
    text = retention_str.strip().lower()
    num = ""

    for char in text:
        if char.isdigit():
            num += char
        else:
            break

    if not num:
        raise ValueError(
            "Use format: 'N days|weeks|months'"
        )

    value = int(num)
    unit = text[len(num):].strip().rstrip('s')

    if unit not in ("day", "week", "month"):
        raise ValueError("Unit must be day, week, or month")

    return [{"time": [{
        "type": "RETENTION",
        "unitValue": value,
        "unitType": unit.upper()
    }]}]


def build_backup_payload(asset_id, policy_id, stage_id,
                         retention, full=False):
    """Build v3 backup payload"""
    level = "FULL" if full else "SYNTHETIC_FULL"

    return {
        "source": {
            "assetIds": [asset_id],
            "protectionGroupIds": []
        },
        "policy": {
            "id": policy_id,
            "objectives": [{
                "id": stage_id,
                "operation": {"backupLevel": level},
                "retentions": build_retention(retention)
            }]
        }
    }


def build_restore_payload(restore_type, copy_id,
                          namespace, args,
                          pvc_names=(), k8s_vms=(),
                          storage_class_map=None):
    """Build restore payload from args"""
    type_map = {
        "rto": "RESTORE_TO_ORIGINAL",
        "rte": "TO_EXISTING",
        "rtn": "TO_ALTERNATE"
    }
    restore_action = type_map[restore_type]

    if args.alt_cluster:
        restore_action = "TO_ALTERNATE"

    payload = {
        "restoreType": restore_action,
        "copyIds": [copy_id],
        "description": (
            f"Restore namespace {restore_type}: "
            f"{namespace or 'original'}"
        )
    }

    if restore_type in ("rte", "rtn"):
        target = {
            "namespace": namespace,
            "skipNamespaceResources": args.skip_metadata,
            "targetInventorySourceId": args.cluster_id,
            "overwritePersistentVolumeClaim": (
                not args.no_overwrite_pvc
            ),
            "persistentVolumeClaims": []
        }

        if not args.skip_pvcs:
            for pvc_name in pvc_names:
                pvc_entry = {"name": pvc_name}
                if (storage_class_map
                        and pvc_name in storage_class_map):
                    pvc_entry["alternateStorageClass"] = (
                        storage_class_map[pvc_name]
                    )
                target["persistentVolumeClaims"].append(pvc_entry)

        if k8s_vms and not args.skip_metadata:
            target["overwriteVmConfig"] = True
            target["k8sVirtualMachineNames"] = list(k8s_vms)
            if args.exclude_k8s_vm:
                target["excludeK8sVirtualMachines"] = (
                    args.exclude_k8s_vm
                )

        payload["restoredCopiesDetails"] = {
            "targetK8sInfo": target
        }

    payload["options"] = {
        "includeClusterResources": (
            args.include_cluster_resources
        ),
        "powerOnVm": args.power_on_vm,
        "restoreBiosUuid": args.restore_bios_uuid,
        "includeVirtualMachineResources": (
            bool(k8s_vms) and not args.skip_metadata
        )
    }

    return payload


def parse_timestamp(raw):
    """Parse a PPDM timestamp string into a datetime, or None"""
    ppdm_time_formats = (
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"
    )
    for time_format in ppdm_time_formats:
        try:
            return datetime.strptime(raw, time_format)
        except ValueError:
            continue

    return None


def get_copy_timestamp(copy):
    """Extract backup timestamp from a copy as datetime, or None"""
    raw = copy.get("backupTime", "") or copy.get("creationTime", "")

    return parse_timestamp(raw) if raw else None


def select_copy(copies, copy_id=None, timestamp=None):
    """Select a backup copy by ID, timestamp, or latest"""
    if copy_id:
        for copy in copies:
            if copy["id"] == copy_id:
                return copy
        raise SystemExit("Copy ID not found")

    if timestamp:
        target = None

        user_time_formats = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d")
        for time_format in user_time_formats:
            try:
                target = datetime.strptime(
                    timestamp, time_format
                )
                break
            except ValueError:
                continue

        if not target:
            raise SystemExit("Invalid timestamp format")

        timed_copies = []
        for copy in copies:
            copy_time = get_copy_timestamp(copy)
            if copy_time:
                timed_copies.append((copy, copy_time))

        if not timed_copies:
            raise SystemExit("No copy matches timestamp")

        best_match, _ = min(
            timed_copies,
            key=lambda pair: abs(
                (target - pair[1]).total_seconds()
            )
        )

        return best_match

    return copies[0]


def fmt_time(copy):
    """Format copy timestamp for display"""
    backup_time = get_copy_timestamp(copy)

    if backup_time:
        return backup_time.strftime("%Y-%m-%d %H:%M:%S")

    return "Unknown"


def start_discovery(uri, token, cluster_id):
    """Trigger K8s cluster discovery"""
    endpoint = f"{uri}/discoveries"

    payload = {
        "start": f"/inventory-sources/{cluster_id}",
        "level": "DataCopies"
    }

    response = init_rest_call("POST", endpoint, token, payload)

    if not response:
        raise SystemExit("Failed to start discovery")

    task_id = response.get("taskId")

    if not task_id:
        logger.error("Discovery response: %s",
                     json.dumps(response, indent=2)
                     if isinstance(response, dict)
                     else str(response)[:500])
        raise SystemExit("Discovery response missing taskId")

    return task_id


def perform_backup(uri, token, payload):
    """Start ad-hoc backup"""
    endpoint = f"{uri}/protections"

    response = init_rest_call("POST", endpoint, token, payload)

    if not response:
        raise SystemExit("Failed to start backup")

    try:
        return response["results"][0]["activityId"]
    except (KeyError, IndexError, TypeError):
        logger.error("Unexpected backup response: %s",
                     json.dumps(response, indent=2)
                     if isinstance(response, dict)
                     else str(response)[:500])
        raise SystemExit("Backup response missing activityId")


def perform_restore(uri, token, payload):
    """Start ad-hoc restore"""
    endpoint = f"{uri}/restored-copies"

    response = init_rest_call("POST", endpoint, token, payload)

    if not response:
        raise SystemExit("Failed to start restore")

    activity_id = response.get("activityId")

    if not activity_id:
        logger.error("Unexpected restore response: %s",
                     json.dumps(response, indent=2)
                     if isinstance(response, dict)
                     else str(response)[:500])
        raise SystemExit("Restore response missing activityId")

    return activity_id


def monitor_activity(uri, token, activity_id,
                     timeout=1800):
    """Poll activity status until done or timeout"""
    if not activity_id:
        print("-> No activity ID to monitor")
        return "UNKNOWN"

    logger.info("Monitoring activity %s", activity_id)
    interval = 15
    start = time.time()
    activity_uri = f"{uri}/activities/{activity_id}"

    while time.time() - start < timeout:
        response = init_rest_call("GET", activity_uri, token)
        if not response:
            time.sleep(interval)
            continue

        state = response.get("state")
        progress = response.get("progress", 0)
        timestamp = time.strftime("%H:%M:%S")

        if state == "COMPLETED":
            result = response.get("result", {})
            status = result.get("status", "UNKNOWN")
            elapsed = int(time.time() - start)
            mins, secs = divmod(elapsed, 60)
            logger.info("Activity %s: %s (%s)",
                        activity_id, state, status)
            print(f"-> {timestamp} Activity {activity_id}: {status} "
                  f"({mins}m {secs}s)")

            if status == "FAILED":
                base = activity_uri.rsplit("/", 1)[0]
                resp = init_rest_call(
                    "GET", base, token,
                    params={"filter":
                            f'parentId eq "{activity_id}"'}
                )
                content = (resp or {}).get("content", [])
                child = content[0] if content else {}
                for issue in child.get("result", {}).get("issues", []):
                    msg = issue.get("message", "")
                    print(f"-> {msg}")
                    logger.error("Activity %s: %s",
                                 activity_id, msg)

            return status

        if state in ("SUCCESSFUL", "FAILED", "CANCELLED"):
            logger.info("Activity %s: %s", activity_id, state)
            print(f"-> {timestamp} Activity {activity_id}: {state}")
            final = init_rest_call("GET", activity_uri, token)
            if final:
                result = final.get("result", {})
                for issue in result.get("issues", []):
                    print(f"-> {issue.get('message', '')}")
                    logger.error("Activity %s: %s",
                                 activity_id, issue.get("message"))

            return state

        print(f"-> {timestamp} Activity {activity_id}: {state} ({progress}%)")
        logger.info("Activity %s: %s (%d%%)",
                    activity_id, state, progress)
        time.sleep(interval)

    logger.warning("Activity %s timed out", activity_id)
    print(f"-> Activity {activity_id} timed out")

    return "TIMEOUT"


def save_activity_id(activity_id, outfile):
    """Save activity ID to file"""
    if outfile:
        try:
            with open(outfile, "w") as f:
                f.write(activity_id)
        except (OSError, IOError) as err:
            logger.error("Failed to save activity ID: %s", err)
            print(f"-> Could not save activity ID to {outfile}: {err}")


def read_activity_id(aidfile):
    """Read activity ID from file"""
    try:
        with open(aidfile, "r") as f:
            return f.read().strip()
    except (OSError, IOError) as err:
        raise SystemExit(f"Error reading aidfile: {err}")


def resolve_cluster_id(uri_v2, token, args, cluster_info):
    """Resolve and validate the target cluster ID from args"""
    if args.alt_cluster:
        if args.restore_type not in ("rte", "rtn"):
            raise SystemExit(
                "Error: -alt-cluster requires -rt rte or -rt rtn"
            )
        alt_id = get_cluster_id(uri_v2, token, args.alt_cluster)
        if not alt_id:
            raise SystemExit(
                f"Error: Cluster not found: {args.alt_cluster}"
            )
        args.cluster_id = alt_id
        print(f"\nAlternate cluster: {args.alt_cluster}")
        print(f"Cluster ID: {alt_id}")
        logger.info("Alternate cluster: %s (%s)", args.alt_cluster, alt_id)

    elif not args.cluster_id and cluster_info.get("id"):
        args.cluster_id = cluster_info["id"]
        cluster_name = cluster_info.get("name", "Unknown")
        print(f"\nUsing source cluster: {cluster_name}")
        print(f"Cluster ID: {args.cluster_id}")
        logger.info(
            "Using source cluster: %s (%s)",
            cluster_name, args.cluster_id
        )

    elif args.cluster_id:
        if not validate_cluster_id(uri_v2, token, args.cluster_id):
            raise SystemExit(
                f"Error: Cluster ID not found: {args.cluster_id}"
            )
        print(f"\nTarget cluster ID: {args.cluster_id}")
        logger.info("Target cluster: %s", args.cluster_id)

    else:
        raise SystemExit("Error: Could not determine cluster ID")


def resolve_target_namespace(uri, token, args):
    """Resolve and validate the target namespace for restore"""
    if args.restore_type not in ("rtn", "rte"):
        return args.namespace

    if args.target_ns:
        target_ns = args.target_ns
    elif args.restore_type == "rtn":
        target_ns = (
            f"{args.namespace}-restore-"
            f"{time.strftime('%b-%y').lower()}"
        )
    else:
        target_ns = args.namespace

    target_ns = target_ns.lower().replace("_", "-").replace(".", "-")

    if args.restore_type == "rtn" and namespace_exists(uri, token, target_ns):
        msg = (
            f"Error: Target namespace '{target_ns}' already exists. "
            f"Use -target-ns to specify a different name."
        )
        raise SystemExit(msg)

    print(f"Target namespace: {target_ns}")
    logger.info("Target namespace: %s", target_ns)

    return target_ns


def build_storage_class_map(uri_v2, token, args, pvc_names, pvc_sc, copy_id):
    """Query and build PVC storage class mapping for the target cluster"""
    sc_map = get_storage_classes(uri_v2, token, args.cluster_id, copy_id)
    storage_class_map = {}

    for pvc_name in pvc_names:
        available = sc_map.get(pvc_name, [])
        if args.storage_class:
            if args.storage_class in available:
                storage_class_map[pvc_name] = args.storage_class
                print(f"  {pvc_name}: {args.storage_class}")
            else:
                print(
                    f"  {pvc_name}: '{args.storage_class}' not "
                    f"available, keeping original"
                )
        else:
            orig_sc = pvc_sc.get(pvc_name, "")
            print(f"  {pvc_name}: {orig_sc}")
            if available and orig_sc not in available:
                print(
                    f"  Warning: '{orig_sc}' not on target. "
                    f"Available: {', '.join(available)}"
                )
                logger.info("%s: '%s' not on target", pvc_name, orig_sc)

    return storage_class_map


def print_restore_options(args, k8s_vms):
    """Print and log restore options summary"""
    rt_labels = {
        "rto": "Restore to Original",
        "rte": "Restore to Existing",
        "rtn": "Restore to New"
    }
    rt_label = rt_labels[args.restore_type]
    if args.alt_cluster:
        rt_label += f" (Alternate Cluster: {args.alt_cluster})"
    sc_label = args.storage_class if args.storage_class else "Default"
    exclude_vms = ", ".join(args.exclude_k8s_vm) if args.exclude_k8s_vm else "False"

    print("\nOptions:")
    print(f"  Restore type                      : {rt_label}")
    print(f"  Skip metadata (PVCs only)         : {args.skip_metadata}")
    print(f"  Skip PVCs (metadata only)         : {args.skip_pvcs}")
    print(f"  Include cluster-scoped resources  : {args.include_cluster_resources}")
    print(f"  Overwrite PVCs                    : {not args.no_overwrite_pvc}")
    print(f"  Power on VMs                      : {args.power_on_vm}")
    print(f"  Restore VM BIOS UUID              : {args.restore_bios_uuid}")
    print(f"  Exclude VMs                       : {exclude_vms}")
    print(f"  Storage Class                     : {sc_label}")

    logger.info(
        "Restore options: type=%s, skip_metadata=%s, skip_pvcs=%s, cluster_resources=%s, "
        "overwrite_pvc=%s, power_on_vm=%s, restore_bios_uuid=%s, "
        "exclude_vms=%s, storage_class=%s",
        rt_label, args.skip_metadata, args.skip_pvcs, args.include_cluster_resources,
        not args.no_overwrite_pvc, args.power_on_vm,
        args.restore_bios_uuid, exclude_vms, sc_label
    )


def main():
    """Main entry point"""
    args = get_args()
    setup_logger(args.log_file)

    if args.skip_metadata and args.skip_pvcs:
        raise SystemExit(
            "Error: -skip-metadata and -skip-pvcs are mutually exclusive"
        )

    if args.envpassword:
        password = os.environ.get("PPDM_PASSWORD")
        if not password:
            raise SystemExit("Error: PPDM_PASSWORD not set")
    elif args.password:
        password = args.password
    else:
        raise SystemExit("Error: -p or -envpassword required")

    token = authenticate(args.ppdm, args.username, password)

    if not token:
        raise SystemExit(1)

    uri = get_api_base(args.ppdm, token)
    uri_v2 = f"https://{args.ppdm}:8443/api/v2"
    action = args.action

    if action == "list":
        if not args.namespace:
            raise SystemExit("Error: -ns required for list")
        logger.info("Action: list, namespace: %s", args.namespace)

        asset_id, policy, cluster_info = get_namespace_asset(
            uri, token, args.namespace, args.cluster
        )
        ns_status = "PROTECTED" if policy.get("id") else "UNPROTECTED"
        ns_policy = policy.get("name", "N/A")

        copies = get_copies(
            uri, token, asset_id, args.timeframe
        )
        last_backup = fmt_time(copies[0]) if copies else None

        latest = copies[0] if copies else None
        extended = latest.get("extendedData", {}) if latest else {}
        pvcs_in_copy = extended.get("persistentVolumeClaims", [])
        vms = extended.get("k8sVirtualMachines", [])

        copies_list = []
        for copy in copies[:10]:
            size_gb = copy.get("sizeInBytes", 0) / (1024 ** 3)
            copies_list.append({
                "timestamp": fmt_time(copy),
                "id": f"{copy['id'][:8]}...",
                "size_gb": f"{size_gb:.2f}",
                "trigger": copy.get("triggerType", "")
            })

        pvcs_list = []
        for pvc in pvcs_in_copy:
            size_gb = pvc.get("size", 0) / (1024 ** 3)
            excluded = "yes" if pvc.get("excluded") else "no"
            pvcs_list.append({
                "name": pvc.get("name", ""),
                "storage_class": pvc.get("storageClass", ""),
                "size_gb": f"{size_gb:.2f}",
                "excluded": excluded
            })

        data = {
            "namespace": args.namespace,
            "status": ns_status,
            "policy": ns_policy,
            "last_backup": last_backup or "No backups found",
            "copies": copies_list,
            "pvcs_in_latest_copy": pvcs_list,
            "vms_in_latest_copy": [vm.get("name", "") for vm in vms]
        }

        format_output(data, args.output)
        print()

    elif action == "backup":
        if not args.namespace:
            raise SystemExit("Error: -ns required for backup")
        if not args.retention:
            raise SystemExit("Error: -ret required for backup")
        logger.info(
            "Action: backup, namespace: %s, retention: %s",
            args.namespace, args.retention
        )

        asset_id, policy, cluster_info = get_namespace_asset(
            uri, token, args.namespace, args.cluster
        )

        if not policy.get("id"):
            raise SystemExit(
                f"'{args.namespace}' has no policy"
            )

        policy_id = policy["id"]
        stage_id = get_backup_stage_id(
            uri, token, policy_id
        )
        payload = build_backup_payload(
            asset_id, policy_id, stage_id,
            args.retention, args.full
        )
        activity_id = perform_backup(uri, token, payload)
        print(f"Backup started: {activity_id}")
        save_activity_id(activity_id, args.outfile)

        if not args.nmonitor:
            status = monitor_activity(
                uri, token, activity_id
            )
            print(f"\nBackup completed with status: {status}")

    elif action == "restore":
        if not args.namespace:
            raise SystemExit("Error: -ns required for restore")
        if not args.restore_type:
            raise SystemExit("Error: -rt or --restore-type required")
        logger.info(
            "Action: restore, namespace: %s, type: %s",
            args.namespace, args.restore_type
        )

        asset_id, policy, cluster_info = get_namespace_asset(
            uri, token, args.namespace, args.cluster
        )

        if not policy.get("id"):
            raise SystemExit(f"'{args.namespace}' has no policy")

        resolve_cluster_id(uri_v2, token, args, cluster_info)
        target_ns = resolve_target_namespace(uri, token, args)

        copies = get_copies(uri, token, asset_id)

        if not copies:
            raise SystemExit("No backup copies available")

        selected = select_copy(copies, args.copy_id, args.timestamp)
        print(f"\nUsing backup copy: {fmt_time(selected)}")
        print(f"Copy ID: {selected['id']}")
        logger.info(
            "Using copy %s (%s)", fmt_time(selected), selected["id"]
        )

        ext_data = selected.get("extendedData", {})
        pvcs_in_copy = ext_data.get("persistentVolumeClaims", [])
        pvc_names = []
        for pvc in pvcs_in_copy:
            if not pvc.get("excluded", False):
                pvc_names.append(pvc["name"])

        pvc_sc = {}
        for pvc in pvcs_in_copy:
            pvc_sc[pvc["name"]] = pvc.get("storageClass", "")

        print(f"PVCs to restore: {len(pvc_names)}")
        logger.info("PVCs to restore: %s", pvc_names)

        k8s_vms = []
        for vm in ext_data.get("k8sVirtualMachines", []):
            if vm.get("name"):
                k8s_vms.append(vm.get("name"))

        if k8s_vms:
            print(f"K8s VMs detected: {len(k8s_vms)}")
            logger.info("K8s VMs in copy: %s", k8s_vms)

        storage_class_map = None
        if args.alt_cluster or args.storage_class:
            storage_class_map = build_storage_class_map(
                uri_v2, token, args, pvc_names, pvc_sc, selected["id"]
            )

        print_restore_options(args, k8s_vms)

        payload = build_restore_payload(
            args.restore_type, selected["id"],
            target_ns, args,
            pvc_names=pvc_names, k8s_vms=k8s_vms,
            storage_class_map=storage_class_map
        )
        activity_id = perform_restore(uri_v2, token, payload)
        print(f"Restore started: {activity_id}")
        save_activity_id(activity_id, args.outfile)

        if not args.nmonitor:
            status = monitor_activity(uri, token, activity_id)
            print(f"\nRestore completed with status: {status}")

    elif action == "discovery":
        logger.info("Action: discovery")
        cluster_id = None
        cluster_name = None

        if args.cluster_id:
            cluster_id = args.cluster_id
            if not validate_cluster_id(uri_v2, token, cluster_id):
                raise SystemExit(
                    f"Error: Cluster ID not found: "
                    f"{cluster_id}"
                )
        elif args.cluster:
            cluster_id = get_cluster_id(
                uri_v2, token, args.cluster
            )
            if not cluster_id:
                raise SystemExit(
                    f"Error: Cluster not found: "
                    f"{args.cluster}"
                )
            cluster_name = args.cluster
        elif args.namespace:
            _, _, cluster_info = get_namespace_asset(
                uri, token, args.namespace
            )
            cluster_id = cluster_info.get("id")
            cluster_name = cluster_info.get("name")
        else:
            raise SystemExit(
                "Error: -cl, -cluster-id, or -ns required"
            )

        print(f"\nDiscovering cluster: "
              f"{cluster_name or cluster_id}")
        logger.info("Discover cluster: %s (%s)",
                    cluster_name or "N/A", cluster_id)

        task_id = start_discovery(uri_v2, token, cluster_id)
        print(f"Discovery started: {task_id}")
        logger.info("Discovery task: %s", task_id)

        if not args.nmonitor:
            status = monitor_activity(
                uri, token, task_id
            )
            print(f"\nDiscovery completed with status: {status}")

    elif action == "monitor":
        logger.info("Action: monitor")

        if args.activity_id:
            aid = args.activity_id
        elif args.aidfile:
            aid = read_activity_id(args.aidfile)
        else:
            raise SystemExit(
                "Error: -activity_id or -aidfile required"
            )
        status = monitor_activity(uri, token, aid)
        print(f"Activity finished: {status}")


if __name__ == "__main__":
    main()
