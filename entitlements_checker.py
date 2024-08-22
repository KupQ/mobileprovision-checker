def check_entitlements(entitlements: dict) -> dict:
    entitlements_mapping = {
        "com.apple.developer.push-to-talk": "Push to Talk",
        "com.apple.developer.journal.allow": "Journal Allow",
        "com.apple.developer.submerged-shallow-depth-and-pressure": "Shallow Depth and Pressure",
        "com.apple.developer.matter.allow-setup-payload": "Matter Allow Setup Payload",
        "com.apple.developer.networking.wifi-info": "Wi-Fi Information",
        "com.apple.security.application-groups": "App Groups",
        "com.apple.developer.in-app-payments": "In-App Payments",
        "com.apple.developer.associated-domains": "Associated Domains",
        "com.apple.developer.authentication-services.autofill-credential-provider": "Autofill Credential Provider",
        "com.apple.developer.sustained-execution": "Sustained Execution",
        "com.apple.developer.ClassKit-environment": "ClassKit Environment",
        "com.apple.developer.default-data-protection": "Default Data Protection",
        "com.apple.developer.driverkit.communicates-with-drivers": "DriverKit Communicates with Drivers",
        "com.apple.developer.driverkit.allow-third-party-userclients": "DriverKit Allow Third-Party User Clients",
        "com.apple.developer.healthkit": "HealthKit",
        "com.apple.developer.healthkit.access": "HealthKit Access",
        "com.apple.developer.homekit": "HomeKit",
        "com.apple.developer.networking.HotspotConfiguration": "Hotspot Configuration",
        "com.apple.developer.ubiquity-kvstore-identifier": "Ubiquity Key-Value Store Identifier",
        "com.apple.developer.proximity-reader.identity.display": "Proximity Reader Identity Display",
        "com.apple.developer.icloud-services": "iCloud Services",
        "com.apple.developer.icloud-container-environment": "iCloud Container Environment",
        "com.apple.developer.icloud-container-identifiers": "iCloud Container Identifiers",
        "com.apple.developer.managed-app-distribution.install-ui": "Managed App Distribution Install UI",
        "com.apple.developer.icloud-container-development-container-identifiers": "iCloud Container Development Identifiers",
        "com.apple.developer.usernotifications.communication": "User Notifications Communication",
        "com.apple.developer.usernotifications.time-sensitive": "User Notifications Time Sensitive",
        "com.apple.developer.ubiquity-container-identifiers": "Ubiquity Container Identifiers",
        "inter-app-audio": "Inter-App Audio",
        "com.apple.developer.networking.multipath": "Multipath",
        "com.apple.developer.networking.networkextension": "Network Extensions",
        "com.apple.developer.nfc.readersession.formats": "NFC Tag Reading",
        "com.apple.developer.coretelephony.sim-inserted": "CoreTelephony SIM Inserted",
        "aps-environment": "Push Notifications",
        "com.apple.developer.sensitivecontentanalysis.client": "Sensitive Content Analysis Client",
        "com.apple.developer.siri": "SiriKit",
        "com.apple.developer.networking.vpn.api": "VPN API",
        "com.apple.external-accessory.wireless-configuration": "Wireless Accessory Configuration",
        "com.apple.developer.pass-type-identifiers": "Pass Type Identifiers",
        "com.apple.developer.group-session": "Group Session",
        "com.apple.developer.coremedia.hls.interstitial-preview": "HLS Interstitial Preview",
        "com.apple.developer.spatial-audio.profile-access": "Spatial Audio Profile Access",
        "com.apple.developer.coremedia.hls.low-latency": "CoreMedia HLS Low Latency",
        "com.apple.developer.shared-with-you": "Shared With You",
        "com.apple.developer.devicecheck.appattest-environment": "App Attest Environment",
        "com.apple.developer.kernel.extended-virtual-addressing": "Extended Virtual Addressing",
        "com.apple.developer.associated-domains.mdm-managed": "MDM Managed Associated Domains",
        "com.apple.developer.shared-with-you.collaboration": "Shared With You Collaboration",
        "com.apple.developer.networking.slicing.appcategory": "Networking Slicing App Category",
        "com.apple.developer.on-demand-install-capable": "On-Demand Install Capable",
        "com.apple.developer.networking.slicing.trafficcategory": "Networking Slicing Traffic Category",
        "com.apple.developer.healthkit.recalibrate-estimates": "HealthKit Recalibrate Estimates",
        "com.apple.developer.media-device-discovery-extension": "Media Device Discovery Extension",
        "application-identifier": "Application Identifier",
        "com.apple.developer.coremotion.head-pose": "Core Motion Head Pose",
        "keychain-access-groups": "Keychain Access Groups",
        "com.apple.developer.weatherkit": "WeatherKit",
        "com.apple.developer.pay-later-merchandising": "Pay Later Merchandising",
        "get-task-allow": "Get Task Allow",
        "com.apple.developer.team-identifier": "Team Identifier",
        "com.apple.developer.kernel.increased-debugging-memory-limit": "Increased Debugging Memory Limit",
        "com.apple.developer.game-center": "Game Center",
        "com.apple.developer.kernel.increased-memory-limit": "Increased Memory Limit",
        "com.apple.developer.healthkit.background-delivery": "HealthKit Background Delivery",
        "com.apple.developer.fileprovider.testing-mode": "FileProvider Testing Mode",
        "com.apple.developer.user-fonts": "User Fonts",
        "com.apple.developer.applesignin": "Apple Sign-In",
    }

    checked_entitlements = {}

    for key, value in entitlements_mapping.items():
        if key in entitlements:
            entitlement_value = entitlements[key]
            if isinstance(entitlement_value, bool):
                checked_entitlements[value] = {"status": "active"}
            elif isinstance(entitlement_value, list):
                checked_entitlements[value] = {
                    "status": "active",
                    "details": entitlement_value
                }
            elif isinstance(entitlement_value, str):
                checked_entitlements[value] = {
                    "status": "active",
                    "details": entitlement_value
                }
            else:
                checked_entitlements[value] = {"status": "unknown"}
        else:
            checked_entitlements[value] = {"status": "inactive"}

    return checked_entitlements
