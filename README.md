# MacCare signed YARA-X rule feed

This public repository contains the cryptographically signed malware-rule feed
used by MacCare. It intentionally contains no private signing material.

Published files:

- `manifest.json` — catalog metadata and SHA-256 digest
- `manifest.json.sig` — raw Ed25519 signature over the manifest bytes
- `rules.yar` — YARA-X rules
- `rules.yar.sig` — raw Ed25519 signature over the rules
- `public-key.txt` — public verification key embedded in MacCare builds

MacCare requires HTTPS, refuses redirects and cross-origin rule downloads,
verifies both signatures and the digest, and rejects non-increasing catalog
versions. This starter catalog is deliberately narrow and does not replace a
continuously maintained endpoint-protection product.
