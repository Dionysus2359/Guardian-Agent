import json
import yaml
from kubernetes import client, config
from agents.db import get_active_baseline, canonical_hash, insert_approval_queue_entry

def get_live_role(namespace: str, role_name: str):
    config.load_kube_config()
    v1 = client.RbacAuthorizationV1Api()
    try:
        role = v1.read_namespaced_role(name=role_name, namespace=namespace)
        return role
    except client.ApiException as e:
        print(f"Error reading live role: {e}")
        return None

def main():
    sa_name = "backup-controller-sa"
    ns = "ops"
    role_name = "backup-controller-role"
    
    print(f"Checking for drift on SA '{sa_name}' in namespace '{ns}'...")
    
    # Get active baseline
    baseline = get_active_baseline(sa_name, ns)
    if not baseline:
        print("No ACTIVE baseline found in database. Nothing to compare against.")
        return
        
    baseline_hash = baseline["canonical_hash"]
    
    # Get live role
    live_role = get_live_role(ns, role_name)
    if not live_role:
        return
        
    # Extract rules and format to match our schema
    live_rules = []
    if live_role.rules:
        for r in live_role.rules:
            for res in (r.resources or []):
                for v in (r.verbs or []):
                    for ag in (r.api_groups or [""]):
                        live_rules.append({
                            "resource": res,
                            "verb": v,
                            "api_group": ag
                        })
                        
    live_hash = canonical_hash(live_rules)
    
    if live_hash == baseline_hash:
        print("✅ No drift detected. Live cluster matches approved baseline.")
    else:
        print("❌ DRIFT DETECTED!")
        print(f"  Live hash:     {live_hash}")
        print(f"  Baseline hash: {baseline_hash}")
        print("\nAuto-reverting to approved baseline...")
        
        # Apply approved_yaml back to cluster
        import tempfile
        import os
        from kubernetes import utils
        
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'w') as tmp:
                tmp.write(baseline["approved_yaml"])
                
            config.load_kube_config()
            k8s_client = client.ApiClient()
            
            # Delete first to ensure clean state, or use patch (but apply is easier via utils)
            v1 = client.RbacAuthorizationV1Api()
            try:
                v1.patch_namespaced_role(
                    name=role_name, 
                    namespace=ns, 
                    body=yaml.safe_load(baseline["approved_yaml"])
                )
                print("✅ Successfully reverted role to baseline.")
            except Exception as e:
                print(f"Failed to auto-revert: {e}")
                
        finally:
            os.remove(path)
            
        # Check if dangerous verbs were added
        dangerous_verbs = {"bind", "impersonate", "escalate", "approve"}
        risk_tier = "low"
        for rule in live_rules:
            if rule["verb"] in dangerous_verbs:
                risk_tier = "critical"
                break
                
        # Log to approval queue
        insert_approval_queue_entry(baseline["id"], "drift_reverted", risk_tier)
        print(f"Created PENDING_APPROVAL entry in queue with risk tier: {risk_tier}")

if __name__ == "__main__":
    main()
