#!/usr/bin/env python3
"""
PPDM Kubernetes Asset Source Configuration Sync.

Synchronizes k8s cluster configuration from source to target clusters within a
PPDM instance or across instances.

Author: Idan Kentor <idan.kentor@dell.com>
Copyright: Copyright [2026] [Idan Kentor]

Example usage:
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -p "password" -a list
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -envpassword \
      -a list -o json -f sources.json
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -p "password" \
      -a diff -source k8s_prod1 -targets all
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -p "password" \
      -a diff -source k8s_prod1 -targets k8s_dr1 --pod-config
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -p "password" \
      -a sync -source k8s_prod1 -targets k8s_prod2,k8s_dmz1
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -envpassword \
      -a sync -source k8s_prod1 -targets all -exclude k8s_prod1 -apply
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -p "password" \
      -a sync -source k8s_prod1 -targets all --controller-config -apply
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -p "password" \
      -a sync -source k8s_prod1 -targets k8s_dr1 --overwrite -apply
    python ppdm_k8s_config_sync.py -ppdm 10.0.0.1 -envpassword \
      -a sync -source k8s_prod1 -target-ppdm 10.0.0.2 -targets all -apply
"""

import argparse
import datetime
import json
import logging
import logging.handlers
import os
import sys
import requests
import urllib3

urllib3.disable_warnings()
logger = logging.getLogger("ppdm_k8s_config_sync")


def get_args():
    """Gets command line args from the user"""
    parser = argparse.ArgumentParser(
        description="PPDM Kubernetes Asset Source Configuration Sync"
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
        "-a", "--action",
        required=True,
        choices=["list", "diff", "sync"],
        help="Action: list sources, show diff, apply sync",
    )

    parser.add_argument(
        "-source", "--source",
        help="Source cluster name (case-insensitive)",
    )

    parser.add_argument(
        "-targets", "--targets",
        help="Target clusters: 'all' or comma-separated names",
    )

    parser.add_argument(
        "-exclude", "--exclude",
        help="Clusters to exclude from sync (comma-separated)",
    )

    parser.add_argument(
        "--pod-config",
        action="store_true",
        help="Sync only POD_CONFIG configurations",
    )

    parser.add_argument(
        "--controller-config",
        action="store_true",
        help="Sync only controller configuration",
    )

    parser.add_argument(
        "-apply", action="store_true",
        help="Apply changes (default: dry-run only)",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Skip confirmation prompt when applying changes",
    )

    parser.add_argument(
        "--overwrite", action="store_true",
        help="Overwrite target configurations that already exist "
             "(default: only add missing configs, skip existing)",
    )

    parser.add_argument(
        "-o", "--output",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    parser.add_argument(
        "-f", "--filename",
        help="Export output to file",
    )

    parser.add_argument(
        "-log", "--log-file",
        default="ppdm_k8s_config_sync.log",
        help="Log file path (default: ppdm_k8s_config_sync.log)",
    )

    parser.add_argument(
        "-target-ppdm", "--target-ppdm",
        dest="target_ppdm",
        help="Target PPDM server for cross-PPDM sync (default: same as -ppdm)",
    )

    parser.add_argument(
        "-debug", action="store_true",
        help="Show raw inventory sources JSON output",
    )

    args = parser.parse_args()

    if args.pod_config and args.controller_config:
        parser.error(
            "--pod-config and --controller-config are mutually exclusive"
        )

    return args


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
        logger.info("PPDM K8s Config Sync Script Started")
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
    if len(payload_str) > 300:
        preview += "..."

    return preview


def init_rest_call(verb, uri, token, payload=None, params=None):
    """Generic function for REST calls"""
    verify = False
    timeout = 90
    code = (200, 201, 202, 204)
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
        logger.error("Connection timed out: %s - %s", uri, error)
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
                message = (
                    "Authentication failed (401): "
                    f"check username/password for {uri}"
                )
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
        logger.debug("Empty response content for %s %s", verb, uri)
        return True

    log_response_summary(verb, uri, response)

    if uri.endswith("/login"):
        return response.json()["access_token"]

    try:
        return response.json()
    except ValueError:
        return response.content


def authenticate(uri, username, password):
    """Login to PowerProtect Data Manager"""
    uri = f"{uri}/login"

    payload = {"username": username, "password": password}
    logger.info("Attempting login to PPDM API")

    token = init_rest_call("POST", uri, None, payload)

    if token:
        logger.info("Login successful")
    else:
        logger.error("Login failed")

    return token


def get_k8s_sources(uri, token):
    """Return all Kubernetes infrastructure objects (inventory sources)"""
    endpoint = f"{uri}/infrastructure-objects"
    params = {"filter": 'type eq "KUBERNETES_CLUSTER"'}

    response = init_rest_call("GET", endpoint, token, None, params)

    if isinstance(response, dict):
        return response.get("content", [])

    return []


def find_source_by_name(sources, name):
    """Find source by case-insensitive exact match, then substring match"""
    if not name:
        return None
    name_lower = name.lower()

    for source in sources:
        if source.get("name", "").lower() == name_lower:
            return source

    for source in sources:
        if name_lower in source.get("name", "").lower():
            return source

    return None


def resolve_targets(sources, source, targets_arg, exclude_arg):
    """Resolve target list from args"""
    if not targets_arg:
        return []

    source_id = source.get("id", "")

    if targets_arg.lower() == "all":
        targets = []
        for src in sources:
            if src.get("id") != source_id:
                targets.append(src)
    else:
        target_names = []
        for name_raw in targets_arg.split(","):
            target_names.append(name_raw.strip())
        targets = []
        for name in target_names:
            found_target = find_source_by_name(sources, name)
            if found_target:
                targets.append(found_target)
            else:
                print(f"-> Warning: Target '{name}' not found, skipping")
                print("-> Available clusters:")
                for src in sources:
                    print(f"   - {src.get('name', 'Unknown')}")
                logger.warning("Target '%s' not found", name)

    if exclude_arg:
        exclude_names = []
        for exclude_raw in exclude_arg.split(","):
            exclude_names.append(exclude_raw.strip().lower())
        filtered_targets = []
        for target in targets:
            if target.get("name", "").lower() not in exclude_names:
                filtered_targets.append(target)
        targets = filtered_targets
        logger.info("Excluded clusters: %s", exclude_arg)

    logger.info("Resolved %d target(s)", len(targets))
    return targets


def extract_sync_data(source, section="full"):
    """Extract syncable fields from infrastructure object (v3 API)"""
    extended_data = source.get("extendedData", {})

    if section == "pod_config":
        pod_configs = []
        for config in extended_data.get("configurations", []):
            if config.get("type") == "POD_CONFIG":
                pod_configs.append(config)
        return {"configurations": pod_configs}

    if section == "controller_config":
        ctrl_configs = []
        for config in extended_data.get("configurations", []):
            if config.get("type") == "CONTROLLER_CONFIG":
                ctrl_configs.append(config)

        sync_data = {}
        if ctrl_configs:
            sync_data["configurations"] = ctrl_configs
        if "controllerConfiguration" in extended_data:
            sync_data["controllerConfiguration"] = extended_data[
                "controllerConfiguration"
            ]

        return sync_data

    sync_data = {}
    if "configurations" in extended_data:
        sync_data["configurations"] = extended_data["configurations"]
    if "controllerConfiguration" in extended_data:
        sync_data["controllerConfiguration"] = extended_data["controllerConfiguration"]

    return sync_data


def diff_sections(source_data, target_data):
    """Compare sync data between source and target"""
    added = []
    changed = []
    unchanged = []
    config_diff = None

    all_keys = set(source_data) | set(target_data)

    for key in sorted(all_keys):
        src_val = source_data.get(key)
        tgt_val = target_data.get(key)

        if key == "configurations":
            config_diff = diff_configurations(
                src_val or [], tgt_val or []
            )
            continue

        if src_val is not None and tgt_val is None:
            added.append(key)
        elif src_val != tgt_val:
            changed.append(key)
        else:
            unchanged.append(key)

    return {
        "added": added,
        "changed": changed,
        "unchanged": unchanged,
        "config_diff": config_diff,
    }


def diff_configurations(source_configs, target_configs):
    """Compare configuration arrays by key

    Classifies each source config as:
    - missing: exists on source but not on target (will be applied)
    - existing: exists on both source and target (skipped unless --overwrite)
    """
    source_keys = set()
    for config in source_configs:
        key = config.get("key")
        if key:
            source_keys.add(key)

    target_keys = set()
    for config in target_configs:
        key = config.get("key")
        if key:
            target_keys.add(key)

    missing = sorted(source_keys - target_keys)
    existing = sorted(source_keys & target_keys)

    return {"missing": missing, "existing": existing}


def format_diff(diff, target_name, overwrite=False):
    """Format diff for human-readable output"""
    lines = []
    lines.append(f"\nTarget: {target_name}")
    lines.append("-" * 50)

    has_changes = False

    if diff["added"]:
        has_changes = True
        lines.append("  Fields to ADD (present in source, missing in target):")
        for key in diff["added"]:
            lines.append(f"    + {key}")

    if diff["changed"]:
        has_changes = True
        lines.append("  Fields with different values:")
        for key in diff["changed"]:
            lines.append(f"    ~ {key}")

    config_diff = diff.get("config_diff")
    if config_diff:
        if config_diff["missing"]:
            has_changes = True
            lines.append("  Configurations to ADD (missing on target):")
            for config_key in config_diff["missing"]:
                lines.append(f"    + {config_key}")

        if config_diff["existing"]:
            has_changes = True
            if overwrite:
                lines.append(
                    "  Configurations to OVERWRITE (--overwrite enabled):"
                )
            else:
                lines.append(
                    "  Configurations SKIPPED (already exist on target):"
                )
            for config_key in config_diff["existing"]:
                lines.append(f"    = {config_key}")

    if not has_changes:
        lines.append("  No configuration differences found.")

    return "\n".join(lines)


def merge_configurations(source_configs, target_configs, overwrite=False):
    """Merge source configs into target: add missing, optionally overwrite"""
    target_by_key = {}
    for config in target_configs:
        key = config.get("key")
        if key:
            target_by_key[key] = config

    source_by_key = {}
    for config in source_configs:
        key = config.get("key")
        if key:
            source_by_key[key] = config

    merged = []
    for config in target_configs:
        key = config.get("key")
        if overwrite and key in source_by_key:
            merged.append(source_by_key[key])
        else:
            merged.append(config)

    for key, config in source_by_key.items():
        if key not in target_by_key:
            merged.append(config)

    return merged


def build_sync_payload(target, sync_data, section="full", overwrite=False):
    """Build PATCH payload with minimal required fields (v3 API)"""
    payload = {
        "categories": ["INVENTORY_SOURCE"],
        "name": target.get("name"),
        "type": target.get("type"),
    }

    if "connectionDetails" in target:
        payload["connectionDetails"] = target["connectionDetails"]

    if "vmwVcenterRef" in target:
        payload["vmwVcenterRef"] = {"id": target["vmwVcenterRef"]["id"]}

    extended_data = target.get("extendedData", {}).copy()

    for key, value in sync_data.items():
        if key == "configurations":
            target_configs = extended_data.get("configurations", [])
            extended_data["configurations"] = merge_configurations(
                value, target_configs, overwrite
            )
        else:
            extended_data[key] = value

    payload["extendedData"] = extended_data

    return payload


def apply_sync(uri, token, target_id, payload):
    """Apply configuration to target infrastructure object via PATCH"""
    endpoint = f"{uri}/infrastructure-objects/{target_id}"
    response = init_rest_call("PATCH", endpoint, token, payload)

    if response is not False:
        logger.info("Sync applied to %s", target_id)
        return response

    logger.error("Sync failed for %s", target_id)
    return False


def format_source_table(sources):
    """Format asset sources as human-readable table"""
    if not sources:
        return "No Kubernetes asset sources found.\n"

    lines = []
    lines.append("\nKubernetes Asset Sources:")
    lines.append("=" * 70)
    lines.append("")

    for source in sources:
        name = source.get("name", "Unknown")
        version = source.get("version", "N/A")
        source_id = source.get("id", "")
        extended_data = source.get("extendedData", {})
        configurations = extended_data.get("configurations", [])
        controller = extended_data.get("controllerConfiguration", {})
        dist_type = extended_data.get("distributionType", "N/A")
        lines.append(f"  Name:           {name}")
        lines.append(f"  ID:             {source_id}")
        lines.append(f"  Version:        {version}")
        lines.append(f"  Distribution:   {dist_type}")
        lines.append(f"  Configurations: {len(configurations)}")
        if configurations:
            for config in configurations:
                config_type = config.get("type", "Unknown")
                key = config.get("key", "Unknown")
                lines.append(f"    - Type: {config_type}, Key: {key}")
        if controller:
            lines.append(f"  Controller:     {len(controller)} parameter(s)")
        lines.append("")

    return "\n".join(lines)


def format_source_json(sources):
    """Format asset sources as JSON for export"""
    export = []

    for source in sources:
        entry = {
            "name": source.get("name", "Unknown"),
            "id": source.get("id", ""),
            "version": source.get("version", "N/A"),
        }
        extended_data = source.get("extendedData", {})
        configurations = extended_data.get("configurations", [])
        controller = extended_data.get("controllerConfiguration", {})
        config_keys = []
        for config in configurations:
            config_keys.append(config.get("key", "unknown"))
        entry["distribution_type"] = extended_data.get(
            "distributionType", "N/A"
        )
        entry["configuration_keys"] = config_keys
        entry["controller_parameters"] = len(controller)
        export.append(entry)

    return json.dumps(export, indent=2)


def export_output(content, filename):
    """Export output content to file"""
    try:
        with open(filename, "w", encoding="utf-8") as file_handle:
            file_handle.write(content)
        print(f"-> Exported to {filename}")
        logger.info("Output exported to %s", filename)
    except (OSError, IOError) as error:
        print(f"-> Failed to export to {filename}: {error}")
        logger.error("Export failed: %s - %s", filename, error)


def main():
    """Main execution"""
    # Args assignment
    args = get_args()

    # Initialize logger
    setup_logger(args.log_file)

    # Get password from command line argument or environment variable
    if args.password:
        password = args.password
    elif args.env_password:
        password = os.environ.get("PPDM_PASSWORD")
        if not password:
            print("-> PPDM_PASSWORD environment variable is not set")
            logger.error("PPDM_PASSWORD environment variable is not set")
            raise SystemExit(1)
    else:
        print("-> Password required (use -p or -envpassword)")
        logger.error("Password not provided")
        raise SystemExit(1)

    # Const definition
    api_port = 8443
    api_v2_endpoint = "/api/v2"
    api_v3_endpoint = "/api/v3"
    uri_v2 = f"https://{args.ppdm}:{api_port}{api_v2_endpoint}"
    uri_v3 = f"https://{args.ppdm}:{api_port}{api_v3_endpoint}"

    # Logs into the PPDM API
    token = authenticate(uri_v2, args.username, password)
    if not token:
        print("-> Login failed")
        raise SystemExit(1)

    # Fetch K8s inventory sources
    sources = get_k8s_sources(uri_v3, token)
    if not sources:
        print("-> No Kubernetes inventory sources found")
        logger.info("No K8s inventory sources found")
        raise SystemExit(0)

    logger.info("Found %d K8s inventory source(s)", len(sources))

    if args.debug:
        print("\nRaw inventory-sources output:")
        print(json.dumps(sources, indent=2))
        print()

    # Action: list
    if args.action == "list":
        if args.output == "json":
            content = format_source_json(sources)
        else:
            content = format_source_table(sources)
        print(content)
        if args.filename:
            export_output(content, args.filename)
        raise SystemExit(0)

    # Cross-PPDM: authenticate and fetch targets from target PPDM
    if args.target_ppdm:
        target_uri_v2 = f"https://{args.target_ppdm}:{api_port}{api_v2_endpoint}"
        target_uri_v3 = f"https://{args.target_ppdm}:{api_port}{api_v3_endpoint}"
        if args.env_password:
            target_env_pwd = os.environ.get("PPDM_TARGET_PASSWORD")
            if target_env_pwd:
                target_password = target_env_pwd
                print("-> Target PPDM: using PPDM_TARGET_PASSWORD")
            else:
                target_password = password
                print("-> Target PPDM: PPDM_TARGET_PASSWORD not set, using PPDM_PASSWORD")
        else:
            target_password = password
        target_token = authenticate(target_uri_v2, args.username, target_password)
        if not target_token:
            print(f"-> Login failed for target PPDM {args.target_ppdm}")
            raise SystemExit(1)
        target_sources = get_k8s_sources(target_uri_v3, target_token)
        if not target_sources:
            print(f"-> No K8s sources found on target PPDM {args.target_ppdm}")
            raise SystemExit(0)
        logger.info(
            "Target PPDM %s: found %d K8s source(s)",
            args.target_ppdm, len(target_sources)
        )
    else:
        target_uri_v3 = uri_v3
        target_token = token
        target_sources = sources

    # Validate source and targets for diff/sync
    if not args.source:
        print("-> Source cluster name required for diff/sync actions")
        logger.error("Source cluster name not provided")
        raise SystemExit(1)

    source = find_source_by_name(sources, args.source)
    if not source:
        print(f"-> Source cluster '{args.source}' not found")
        print("-> Available clusters:")
        for src in sources:
            print(f"   - {src.get('name', 'Unknown')}")
        logger.error("Source '%s' not found", args.source)
        raise SystemExit(1)

    if not args.targets:
        print("-> Targets required for diff/sync actions")
        logger.error("Targets not provided")
        raise SystemExit(1)

    # Resolve targets and extract source sync data
    targets = resolve_targets(
        target_sources, source, args.targets, args.exclude
    )
    if not targets:
        print("-> No targets to process")
        raise SystemExit(0)

    if args.pod_config:
        section = "pod_config"
    elif args.controller_config:
        section = "controller_config"
    else:
        section = "full"

    source_name = source.get("name")
    source_data = extract_sync_data(source, section)
    logger.info(
        "Source '%s' sync data extracted (%s): %d field(s)",
        source_name, section, len(source_data)
    )

    # Action: diff
    if args.action == "diff":
        if args.target_ppdm:
            print(
                f"\nDiff: Source '{source_name}' ({args.ppdm})"
                f" vs {len(targets)} target(s) on {args.target_ppdm}"
            )
        else:
            print(f"\nDiff: Source '{source_name}' vs {len(targets)} target(s)")
        if section != "full":
            section_label = {
                "pod_config": "POD_CONFIG configurations",
                "controller_config": "controller configuration",
            }[section]
            print(f"Section: {section_label}")
        print("=" * 70)

        diff_results = []
        for target in targets:
            target_name = target.get("name", "Unknown")
            target_data = extract_sync_data(target, section)
            diff = diff_sections(source_data, target_data)
            diff_results.append({
                "target": target_name,
                "diff": diff,
            })
            print(format_diff(diff, target_name, args.overwrite))

        if args.output == "json" and args.filename:
            json_export = []
            for result in diff_results:
                entry = {"target": result["target"]}
                diff_data = result["diff"]
                entry["added"] = diff_data["added"]
                entry["changed"] = diff_data["changed"]
                entry["unchanged"] = diff_data["unchanged"]
                config_diff = diff_data.get("config_diff")
                if config_diff:
                    entry["configs_missing"] = config_diff["missing"]
                    entry["configs_existing"] = config_diff["existing"]
                json_export.append(entry)

            export_output(json.dumps(json_export, indent=2), args.filename)

        raise SystemExit(0)

    # Action: sync
    if args.action == "sync":
        if args.target_ppdm:
            print(
                f"\nSync: Source '{source_name}' ({args.ppdm})"
                f" -> {len(targets)} target(s) on {args.target_ppdm}"
            )
        else:
            print(f"\nSync: Source '{source_name}' -> {len(targets)} target(s)")
        if section != "full":
            section_label = {
                "pod_config": "Pod configurations",
                "controller_config": "controller configuration",
            }[section]
            print(f"Section: {section_label}")
        if args.overwrite:
            print("Mode: OVERWRITE (existing target configs will be replaced)")
        else:
            print("Mode: ADD-ONLY (existing target configs will be preserved)")
        print("=" * 70)

        # Show diffs for all targets
        for target in targets:
            target_name = target.get("name", "Unknown")
            target_data = extract_sync_data(target, section)
            diff = diff_sections(source_data, target_data)
            print(format_diff(diff, target_name, args.overwrite))
            config_diff = diff.get("config_diff")
            if config_diff and config_diff["existing"]:
                if args.overwrite:
                    logger.info(
                        "Target '%s': overwriting configs: %s",
                        target_name,
                        ", ".join(config_diff["existing"])
                    )
                else:
                    logger.info(
                        "Target '%s': skipping existing configs: %s",
                        target_name,
                        ", ".join(config_diff["existing"])
                    )

        if not args.apply:
            print("\n-> Dry-run mode: no changes applied")
            print("-> Use -apply to apply changes")
            raise SystemExit(0)

        # Confirmation prompt — skipped when quiet or specific targets named
        targets_all = args.targets.lower() == "all"
        if not args.quiet and targets_all:
            response = input("\nApply changes to all targets? (yes/no): ")
            if response.lower() != "yes":
                print("-> Sync cancelled")
                logger.info("Sync cancelled by user")
                raise SystemExit(0)

        # Apply sync to each target
        print("\nApplying configuration changes...")
        logger.info("Applying sync to %d target(s)", len(targets))
        success_count = 0
        fail_count = 0

        for target in targets:
            target_id = target.get("id")
            target_name = target.get("name", "Unknown")
            logger.info(
                "Pre-sync config for '%s': %s",
                target_name,
                json.dumps(extract_sync_data(target, section))[:500]
            )
            payload = build_sync_payload(
                target, source_data, section, args.overwrite
            )
            result = apply_sync(target_uri_v3, target_token, target_id, payload)
            if result is not False:
                print(f"  OK: {target_name}")
                success_count += 1
            else:
                print(f"  FAILED: {target_name}")
                fail_count += 1

        print(
            f"\nSync complete: {success_count} succeeded, "
            f"{fail_count} failed"
        )
        logger.info(
            "Sync complete: %d succeeded, %d failed",
            success_count, fail_count
        )

        if fail_count > 0:
            raise SystemExit(1)

        raise SystemExit(0)


if __name__ == "__main__":
    main()
