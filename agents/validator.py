ALLOWED_API_GROUPS = {"", "rbac.authorization.k8s.io", "apps", "batch", "extensions", "networking.k8s.io"}

def validate_rules(rules: list[dict]) -> tuple[bool, list[str]]:
    """
    Validates a list of permission rules.
    Returns (is_valid, list_of_errors).
    """
    errors = []
    
    for rule in rules:
        # Check wildcards
        if "*" in rule.get("verbs", []):
            errors.append(f"Wildcard verb '*' is not allowed.")
        if "*" in rule.get("resources", []):
            errors.append(f"Wildcard resource '*' is not allowed.")
        
        # apiGroups might be a list or string depending on how it's passed, but K8s expects list
        api_groups = rule.get("apiGroups", rule.get("api_group", []))
        if isinstance(api_groups, str):
            api_groups = [api_groups]
            
        if "*" in api_groups:
            errors.append(f"Wildcard apiGroup '*' is not allowed.")
            
        for ag in api_groups:
            if ag not in ALLOWED_API_GROUPS:
                errors.append(f"API Group '{ag}' is not in the allowlist.")
                
    return len(errors) == 0, errors
