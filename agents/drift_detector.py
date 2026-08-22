"""
Permission Gap / Drift Detector

USAGE:
    python agents/drift_detector.py --audit <path_to_audit_json> --yaml <path_to_rbac_yaml>

EXAMPLE (using defaults):
    python agents/drift_detector.py --audit guardian_audit.json --yaml k8s/target_setup.yaml

OUTPUT:
    Generates 'drift_report.txt' (for humans) and 'drift_report.json' (for Streamlit dashboard)
"""

import argparse
import json
import yaml
import sys
from datetime import datetime, timezone
import os

def load_yaml_roles(yaml_path):
    granted = set()
    try:
        with open(yaml_path, 'r') as f:
            docs = yaml.safe_load_all(f)
            for doc in docs:
                if not doc:
                    continue
                kind = doc.get("kind")
                if kind in ("Role", "ClusterRole"):
                    rules = doc.get("rules", [])
                    for rule in rules:
                        api_groups = rule.get("apiGroups", [""])
                        resources = rule.get("resources", [])
                        verbs = rule.get("verbs", [])
                        
                        for ag in api_groups:
                            for res in resources:
                                for v in verbs:
                                    # store as a tuple (apiGroup, resource, verb)
                                    granted.add((ag, res, v))
    except Exception as e:
        print(f"Error loading YAML {yaml_path}: {e}")
    return granted

def load_audit_json(audit_path):
    try:
        with open(audit_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading Audit JSON {audit_path}: {e}")
        return {}

def main():
    parser = argparse.ArgumentParser(description="Permission Gap / Drift Detector")
    parser.add_argument("--audit", type=str, default="guardian_audit.json", help="Path to guardian_audit.json (used permissions)")
    parser.add_argument("--yaml", type=str, default="k8s/target_setup.yaml", help="Path to RBAC YAML file (granted permissions)")
    parser.add_argument("--output", type=str, default="drift_report", help="Prefix for output files (e.g. drift_report)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.yaml):
        print(f"Warning: {args.yaml} not found.")
    if not os.path.exists(args.audit):
        print(f"Warning: {args.audit} not found.")
        
    granted_perms = load_yaml_roles(args.yaml)
    audit_data = load_audit_json(args.audit)
    
    reports = []
    
    service_accounts = audit_data.get("service_accounts", [])
    if not service_accounts:
        # Fallback if a single SA object is passed instead of the expected list wrapper
        if "service_account" in audit_data:
            service_accounts = [audit_data]
        else:
            print("No service accounts found in audit data.")
            
    for sa_entry in service_accounts:
        sa_name = sa_entry.get("service_account", "unknown")
        ns = sa_entry.get("namespace", "unknown")
        
        used_perms = set()
        
        if "permissions_used" in sa_entry:
            for p in sa_entry["permissions_used"]:
                ag = p.get("api_group", "")
                res = p.get("resource", "")
                verb = p.get("verb", "")
                used_perms.add((ag, res, verb))
        
        granted_but_unused = granted_perms - used_perms
        used_and_granted = used_perms & granted_perms
        used_but_not_granted = used_perms - granted_perms
        
        report = {
            "service_account": sa_name,
            "namespace": ns,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "granted_but_unused": [{"api_group": g[0], "resource": g[1], "verb": g[2]} for g in sorted(granted_but_unused)],
            "used_and_granted": [{"api_group": g[0], "resource": g[1], "verb": g[2]} for g in sorted(used_and_granted)],
            "used_but_not_granted": [{"api_group": g[0], "resource": g[1], "verb": g[2]} for g in sorted(used_but_not_granted)]
        }
        reports.append(report)
        
        # Generate Text Report
        txt_path = f"{args.output}.txt"
        with open(txt_path, "w") as f:
            f.write("=== Permission Gap Report ===\n")
            f.write(f"Service Account: {sa_name}\n")
            f.write(f"Namespace: {ns}\n")
            f.write(f"Generated: {report['timestamp']}\n\n")
            
            f.write("--- GRANTED BUT UNUSED (potential over-privilege) ---\n")
            if not granted_but_unused:
                f.write("  (none)\n")
            for p in sorted(granted_but_unused):
                ag = p[0] if p[0] else "core"
                f.write(f"  • {p[1]} / {p[2]} ({ag})\n")
            f.write("\n")
            
            f.write("--- USED AND GRANTED (confirmed necessary) ---\n")
            if not used_and_granted:
                f.write("  (none)\n")
            for p in sorted(used_and_granted):
                ag = p[0] if p[0] else "core"
                f.write(f"  • {p[1]} / {p[2]} ({ag})\n")
            f.write("\n")
            
            f.write("--- USED BUT NOT GRANTED (anomaly) ---\n")
            if not used_but_not_granted:
                f.write("  (none)\n")
            for p in sorted(used_but_not_granted):
                ag = p[0] if p[0] else "core"
                f.write(f"  • {p[1]} / {p[2]} ({ag})\n")
            f.write("\n")
            
            total_granted = len(granted_perms)
            f.write(f"Summary: {len(granted_but_unused)} unused permissions found out of {total_granted} total granted.\n")
            print(f"Generated text report at {txt_path}")
            
    json_path = f"{args.output}.json"
    with open(json_path, "w") as f:
        json.dump(reports, f, indent=2)
        print(f"Generated JSON report at {json_path}")

if __name__ == "__main__":
    main()
