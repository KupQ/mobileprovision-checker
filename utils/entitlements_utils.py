def check_entitlements(entitlements: dict) -> dict:
    entitlements_mapping = {
        "com.apple.developer.push-to-talk": "Push to Talk",
        # Add the rest of the entitlements mappings here
    }

    return {entitlements_mapping[key]: {"status": "active"} for key in entitlements if key in entitlements_mapping}
