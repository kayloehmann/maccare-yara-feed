/*
 * MacCare embedded YARA-X starter catalog.
 *
 * The app bundle's code signature protects this built-in catalog. Downloaded
 * updates are accepted only through SignedRuleStore after Ed25519 verification.
 * Exact-hash rules below are high-confidence indicators from the cited public
 * research. They intentionally trade breadth for a very low false-positive
 * rate. The EICAR rule is a harmless self-test, not a malware verdict.
 */

import "hash"

rule MacCare_EICAR_SelfTest : self_test quarantine
{
    meta:
        display_name = "EICAR antivirus self-test"
        family = "EICAR"
        confidence = "self-test"
        quarantine = true
        source = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule MacCare_macOS_Gaslight_SHA256 : macos known_malware quarantine
{
    meta:
        display_name = "macOS.Gaslight"
        family = "Gaslight"
        confidence = "high"
        quarantine = true
        source = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"

    condition:
        filesize < 256MB and
        hash.sha256(0, filesize) == "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"
}

rule MacCare_macOS_Gaslight_Sibling_SHA256 : macos known_malware quarantine
{
    meta:
        display_name = "macOS.Gaslight related BONZAI sample"
        family = "Gaslight/BONZAI"
        confidence = "high"
        quarantine = true
        source = "https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/"

    condition:
        filesize < 256MB and
        hash.sha256(0, filesize) == "77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca"
}

rule MacCare_ResourceFork_MachO_SHA256 : macos known_malware quarantine
{
    meta:
        display_name = "Resource-fork macOS malware Mach-O"
        family = "ResourceFork"
        confidence = "high"
        quarantine = true
        source = "https://www.sentinelone.com/labs/resourceful-macos-malware-hides-in-named-fork/"

    condition:
        filesize < 256MB and
        hash.sha256(0, filesize) == "43b9157a4ad42da1692cfb5b571598fcde775c7d1f9c7d56e6d6c13da5b35537"
}

rule MacCare_ResourceFork_DMG_SHA256 : macos known_malware quarantine
{
    meta:
        display_name = "Resource-fork macOS malware disk image"
        family = "ResourceFork"
        confidence = "high"
        quarantine = true
        source = "https://www.sentinelone.com/labs/resourceful-macos-malware-hides-in-named-fork/"

    condition:
        filesize < 1024MB and
        hash.sha256(0, filesize) == "5673ace10a07905503486f5f4eeb8d45a4d56a2168b0274084750f68eb7a1362"
}
