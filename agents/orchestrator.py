import json
import os
import argparse
import uuid
import yaml
from datetime import datetime
from typing import TypedDict, Literal
import sqlite3
import argparse

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite import SqliteSaver
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_ollama import ChatOllama
from jinja2 import Environment, FileSystemLoader
from kubernetes import client, config, utils

from agents.validator import validate_rules
from agents.db import (
    canonical_hash, check_broken_rollback, store_baseline,
    insert_approval_queue_entry, DB_PATH
)

# ---- State Definition ----
class GuardianState(TypedDict):
    sa_data: dict
    resource_version: str
    
    llm_analysis: dict
    risk_assessment: dict
    policy_decision: dict
    generated_yaml: str
    
    route: Literal["auto_apply", "human_queue"]
    retry_count: int
    errors: list[str]

# ---- System Prompts ----
ANALYZER_PROMPT = """
You are a Kubernetes RBAC security analyzer. Analyze the granted vs used permissions.
Output STRICT JSON exactly matching this schema:
{
  "verdict": "revoke" | "keep" | "keep_with_alert" | "escalate_to_human",
  "risky_permissions": [{"resource": "...", "verb": "...", "reason": "..."}],
  "reasoning": "your detailed reasoning string",
  "confidence": <integer 0-100>
}
"""

GENERATOR_PROMPT = """
You are a Kubernetes RBAC policy generator. Based on the previous risk analysis, 
output ONLY the permissions that should be KEPT.
Output STRICT JSON as a list of objects exactly matching this schema:
[
  {"resource": "...", "verb": "...", "api_group": "..."}
]
"""

# ---- Nodes ----
def log_collector(state: GuardianState):
    print("\n--- NODE 1: Log Collector ---")
    # Load mock data
    with open("agents/fixtures/audit.json", "r") as f:
        audit_data = json.load(f)
    with open("agents/fixtures/yaml.json", "r") as f:
        yaml_data = json.load(f)
        
    merged = {
        "service_account": yaml_data["service_account"],
        "namespace": yaml_data["namespace"],
        "granted_permissions": yaml_data["granted_permissions"],
        "used_permissions": audit_data["used_permissions"]
    }
    return {"sa_data": merged, "resource_version": yaml_data.get("resource_version", ""), "retry_count": 0, "errors": []}

def permission_analyzer(state: GuardianState):
    print("\n--- NODE 2: Permission Analyzer ---")
    llm = ChatOllama(model="qwen3:8b", format="json", temperature=0.1)
    
    messages = [
        SystemMessage(content=ANALYZER_PROMPT),
        HumanMessage(content=json.dumps(state["sa_data"]))
    ]
    
    retries = state.get("retry_count", 0)
    try:
        response = llm.invoke(messages)
        analysis = json.loads(response.content)
        print(f"LLM Verdict: {analysis.get('verdict')} (Confidence: {analysis.get('confidence')})")
        return {"llm_analysis": analysis}
    except Exception as e:
        print(f"Failed to parse LLM JSON: {e}")
        return {"retry_count": retries + 1}

def risk_scorer(state: GuardianState):
    print("\n--- NODE 3: Risk Scorer ---")
    analysis = state.get("llm_analysis", {})
    confidence = analysis.get("confidence", 0)
    
    flags = []
    route = "auto_apply"
    
    dangerous_verbs = {"bind", "impersonate", "escalate", "approve"}
    high_value_resources = {"secrets", "rolebindings", "clusterroles"}
    
    granted = state["sa_data"]["granted_permissions"]
    for p in granted:
        if p.get("verb") in dangerous_verbs:
            flags.append(f"Dangerous verb: {p['verb']}")
            confidence = min(confidence, 75)
        if "*" in p.get("verb", "") or "*" in p.get("resource", "") or "*" in p.get("api_group", ""):
            flags.append("Wildcard detected")
            confidence = 0
            
    if state.get("retry_count", 0) > 0:
        confidence = max(0, confidence - 20)
        
    if confidence < 80 or len(flags) > 0:
        route = "human_queue"
        
    print(f"Final Confidence: {confidence}. Route: {route}. Flags: {flags}")
    return {"risk_assessment": {"final_confidence": confidence, "flags": flags}, "route": route}

def policy_generator(state: GuardianState):
    print("\n--- NODE 4: Policy Generator ---")
    llm = ChatOllama(model="qwen3:8b", format="json", temperature=0.1)
    
    input_data = {
        "sa_data": state["sa_data"],
        "analysis": state["llm_analysis"],
        "risk_flags": state["risk_assessment"]["flags"]
    }
    
    messages = [
        SystemMessage(content=GENERATOR_PROMPT),
        HumanMessage(content=json.dumps(input_data))
    ]
    
    response = llm.invoke(messages)
    
    # Strip markdown code blocks if present
    content = response.content.strip()
    if content.startswith("```json"):
        content = content[7:]
    if content.startswith("```"):
        content = content[3:]
    if content.endswith("```"):
        content = content[:-3]
    content = content.strip()
    
    print(f"Raw LLM Output: {content}")
    
    try:
        kept_permissions = json.loads(content)
        if isinstance(kept_permissions, dict):
            # If the LLM returned a single permission object instead of a list
            if "resource" in kept_permissions and "verb" in kept_permissions:
                kept_permissions = [kept_permissions]
            # If the LLM wrapped it in {"permissions": [...]}
            elif "permissions" in kept_permissions:
                kept_permissions = kept_permissions["permissions"]
            else:
                raise ValueError("Expected list of permissions")
        
        if not isinstance(kept_permissions, list) or (len(kept_permissions) > 0 and not isinstance(kept_permissions[0], dict)):
             raise ValueError("Expected list of dicts")
    except Exception as e:
        print(f"Failed to parse LLM JSON: {e}. Falling back to granted_permissions")
        kept_permissions = state["sa_data"]["granted_permissions"]
        
    print(f"Permissions to keep: {len(kept_permissions)}")
    
    # Validate rules
    is_valid, errors = validate_rules(kept_permissions)
    if not is_valid:
        print(f"Validation failed: {errors}")
        return {"route": "human_queue", "errors": state.get("errors", []) + errors}
        
    # Check broken rollback
    phash = canonical_hash(kept_permissions)
    if check_broken_rollback(phash):
        print("Matches BROKEN_ROLLBACK! Rejecting.")
        return {"route": "human_queue", "errors": state.get("errors", []) + ["Hash matched BROKEN_ROLLBACK"]}
        
    # Generate YAML
    env = Environment(loader=FileSystemLoader("agents/templates"))
    template = env.get_template("role.yaml.j2")
    yaml_str = template.render(
        role_name="backup-controller-role",
        namespace=state["sa_data"]["namespace"],
        rules=kept_permissions
    )
    
    return {"policy_decision": {"permissions": kept_permissions}, "generated_yaml": yaml_str}

def execute_auto_apply(state: GuardianState):
    print("\n--- ACT: Auto Apply ---")
    
    ns = state["sa_data"]["namespace"]
    sa = state["sa_data"]["service_account"]
    yaml_str = state["generated_yaml"]
    rv = state["resource_version"]
    
    # Store baseline
    baseline_id = store_baseline(
        state["sa_data"]["service_account"],
        ns,
        yaml_str,
        state["policy_decision"]["permissions"]
    )
    print(f"Stored baseline: {baseline_id}")
    
    # Write payload
    payload = {
        "action": "apply",
        "service_account": state["sa_data"]["service_account"],
        "namespace": ns,
        "new_role_yaml": yaml_str,
        "resource_version": rv,
        "baseline_id": baseline_id
    }
    with open("execution_payload.json", "w") as f:
        json.dump(payload, f, indent=2)
        
    print("Successfully wrote execution_payload.json")
    
    # Apply the YAML to the live cluster since backend team isn't ready
    try:
        config.load_kube_config()
        v1 = client.RbacAuthorizationV1Api()
        role_body = yaml.safe_load(yaml_str)
        
        # We need to explicitly delete the old role and create the new one, 
        # or patch it. Patching is cleaner.
        v1.patch_namespaced_role(
            name="backup-controller-role", 
            namespace=ns, 
            body=role_body
        )
        print("✅ Successfully applied new tightened role to Kubernetes cluster!")
    except Exception as e:
        print(f"Failed to apply to cluster: {e}")
        
    return {}

def route_human_queue(state: GuardianState):
    print("\n--- ACT: Human Queue ---")
    # In reality we'd get the baseline_id of the active one to queue this up against
    print(f"Queued for human review. Errors/Flags: {state.get('errors', [])} / {state['risk_assessment'].get('flags', [])}")
    
    payload = {
        "action": "dry_run",
        "service_account": state["sa_data"]["service_account"],
        "namespace": state["sa_data"]["namespace"],
        "new_role_yaml": state.get("generated_yaml", "")
    }
    with open("execution_payload.json", "w") as f:
        json.dump(payload, f, indent=2)
        
    return {}

def route_decision(state: GuardianState):
    return state.get("route", "human_queue")

# ---- Graph Setup ----
def build_graph():
    workflow = StateGraph(GuardianState)
    
    workflow.add_node("log_collector", log_collector)
    workflow.add_node("permission_analyzer", permission_analyzer)
    workflow.add_node("risk_scorer", risk_scorer)
    workflow.add_node("policy_generator", policy_generator)
    workflow.add_node("auto_apply", execute_auto_apply)
    workflow.add_node("human_queue", route_human_queue)
    
    workflow.set_entry_point("log_collector")
    workflow.add_edge("log_collector", "permission_analyzer")
    workflow.add_edge("permission_analyzer", "risk_scorer")
    workflow.add_edge("risk_scorer", "policy_generator")
    
    workflow.add_conditional_edges(
        "policy_generator",
        route_decision,
        {
            "auto_apply": "auto_apply",
            "human_queue": "human_queue"
        }
    )
    
    workflow.add_edge("auto_apply", END)
    workflow.add_edge("human_queue", END)
    
    return workflow

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--use-fixtures", action="store_true")
    args = parser.parse_args()
    
    conn = sqlite3.connect("checkpoints.db", check_same_thread=False)
    checkpointer = SqliteSaver(conn)
    
    graph = build_graph().compile(checkpointer=checkpointer)
    
    thread_id = f"ops/backup-controller-sa/{datetime.utcnow().isoformat()}"
    run_config = {"configurable": {"thread_id": thread_id}}
    
    print(f"Starting LangGraph Run (Thread: {thread_id})")
    
    initial_state = {
        "sa_data": {},
        "resource_version": "",
        "llm_analysis": {},
        "risk_assessment": {},
        "policy_decision": {},
        "generated_yaml": "",
        "route": "human_queue",
        "retry_count": 0,
        "errors": []
    }
    
    final_state = graph.invoke(initial_state, run_config)
    print("\n--- Run Complete ---")
