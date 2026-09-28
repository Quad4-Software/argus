// Mini Shai-Hulud payload family — obfuscation marker + exfil endpoint.
rule MiniShaiHulud_Payload {
    meta:
        severity = "critical"
        description = "Mini Shai-Hulud obfuscated payload (fc2edea72 decryptor + m-kosche exfil)"
        reference = "https://socket.dev/blog/antv-packages-compromised"
    strings:
        $dec = "fc2edea72" ascii
        $c2a = "m-kosche.com" ascii
        $c2b = "/api/public/otel/v1/traces" ascii
        $hook = "bun run index.js" ascii
    condition:
        $dec or (all of ($c2*)) or ($hook and $dec)
}

rule ShaiHulud_Webhook_Exfil {
    meta:
        severity = "critical"
        description = "Shai-Hulud Sept 2025 webhook.site exfiltration ID"
        reference = "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack"
    strings:
        $w = "webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" ascii
    condition:
        $w
}
