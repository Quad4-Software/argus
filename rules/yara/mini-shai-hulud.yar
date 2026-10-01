// Mini Shai-Hulud payload family  -  obfuscation marker + exfil endpoint.
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

rule ShaiHulud2_SecondComing {
    meta:
        severity = "critical"
        description = "Shai-Hulud 2.0 exfil repo description and runner name"
        reference = "https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/"
    strings:
        $desc = "Sha1-Hulud: The Second Coming" ascii
        $runner = "SHA1HULUD" ascii
        $loader = "setup_bun.js" ascii
    condition:
        any of them
}

rule Axios_Rat_C2 {
    meta:
        severity = "critical"
        description = "axios March 2026 RAT callback"
        reference = "https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/"
    strings:
        $c2 = "sfrclak.com" ascii
    condition:
        $c2
}

rule Keyv_Worm_Markers {
    meta:
        severity = "critical"
        description = "August 2026 keyv/cacheable worm markers"
        reference = "https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack"
    strings:
        $d1 = "npm-cache.com" ascii
        $d2 = "pypi-get.com" ascii
        $d3 = "js-mirror.com" ascii
        $scare = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii
        $dead = "gh-token-monitor" ascii
    condition:
        any of them
}

rule Sckit_C2 {
    meta:
        severity = "critical"
        description = "MemTensor sckit implant markers"
        reference = "https://db.gcve.eu/vuln/PYSEC-2026-3987"
    strings:
        $c2 = "skyleen.fr" ascii
        $id = "memos-semi-nuclear" ascii
    condition:
        any of them
}

rule Qix_Drainer_Address {
    meta:
        severity = "critical"
        description = "September 2025 qix wallet drainer destination"
        reference = "https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack"
    strings:
        $a = "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976" ascii
    condition:
        $a
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
