#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE_DIR="${SCRIPT_DIR}/site"

if [[ ! -f "${SITE_DIR}/app.env" ]]; then
  echo "Missing app.env. Run: bash tests/performance/local/create-keys.sh" >&2
  exit 1
fi

load_app_env() {
  while IFS='=' read -r key value; do
    [[ -z "${key}" || "${key}" == \#* ]] && continue
    printf -v "${key}" '%s' "${value}"
  done < "${SITE_DIR}/app.env"
}

load_app_env

all_actions='"fpe-encrypt", "fpe-decrypt", "token-encode", "token-decode", "mac-create", "mac-verify", "index-create", "index-verify", "mask", "commit-create", "commit-verify", "share-split", "share-combine", "message", "sign", "self-test"'

cat > "${SITE_DIR}/config.json" <<JSON
{
  "version": "v1",
  "routes": [],
  "remote_routes": [],
  "permissions": [
    {
      "client": "${K6_CLIENT}",
      "apikey_hash": "${K6_APIKEY_HASH}",
      "status": "active",
      "permissions": [
        { "kid": "${K6_KID_PERFORMANCE}", "actions": [${all_actions}] },
        { "kid": "${K6_KID_STANDARD}", "actions": [${all_actions}] },
        { "kid": "${K6_KID_HIGH_ASSURANCE}", "actions": [${all_actions}] },
        { "kid": "${K6_KID_LONG_TERM}", "actions": [${all_actions}] },
        { "kid": "*", "actions": ["metrics"] }
      ]
    }
  ],
  "fpe_profiles": [
    { "name": "performance-pan-fpe-v1", "fpe_version": "fpe-ff1-2025", "alphabet": "0123456789", "min_len": 16, "max_len": 16, "tweak_aad": "tenant=k6;field=pan;version=1", "kid": "${K6_KID_PERFORMANCE}" },
    { "name": "standard-ssn-fpe-v1", "fpe_version": "fpe-ff1-2025", "alphabet": "0123456789", "min_len": 9, "max_len": 9, "tweak_aad": "tenant=k6;field=ssn;version=1", "kid": "${K6_KID_STANDARD}" },
    { "name": "high-assurance-bank-fpe-v1", "fpe_version": "fpe-ff1-2025", "alphabet": "0123456789", "min_len": 12, "max_len": 12, "tweak_aad": "tenant=k6;field=bank;version=1", "kid": "${K6_KID_HIGH_ASSURANCE}" },
    { "name": "long-term-account-fpe-v1", "fpe_version": "fpe-ff1-2025", "alphabet": "0123456789", "min_len": 12, "max_len": 12, "tweak_aad": "tenant=k6;field=account;version=1", "kid": "${K6_KID_LONG_TERM}" }
  ],
  "tokenization_profiles": [
    { "name": "performance-pan-token-v1", "kid": "${K6_KID_PERFORMANCE}", "token_prefix": "tok_perf", "token_len": 32, "max_plaintext_len": 128, "one_time": false },
    { "name": "standard-ssn-token-v1", "kid": "${K6_KID_STANDARD}", "token_prefix": "tok_std", "token_len": 32, "max_plaintext_len": 128, "one_time": false },
    { "name": "high-assurance-bank-token-v1", "kid": "${K6_KID_HIGH_ASSURANCE}", "token_prefix": "tok_high", "token_len": 32, "max_plaintext_len": 128, "one_time": true },
    { "name": "long-term-account-token-v1", "kid": "${K6_KID_LONG_TERM}", "token_prefix": "tok_long", "token_len": 32, "max_plaintext_len": 128, "one_time": false }
  ],
  "mac_profiles": [
    { "name": "performance-pan-mac-v1", "kid": "${K6_KID_PERFORMANCE}", "context": "tenant=k6;field=pan;purpose=blind-index;version=1" },
    { "name": "standard-ssn-mac-v1", "kid": "${K6_KID_STANDARD}", "context": "tenant=k6;field=ssn;purpose=blind-index;version=1" },
    { "name": "high-assurance-bank-mac-v1", "kid": "${K6_KID_HIGH_ASSURANCE}", "context": "tenant=k6;field=bank;purpose=blind-index;version=1" },
    { "name": "long-term-account-mac-v1", "kid": "${K6_KID_LONG_TERM}", "context": "tenant=k6;field=account;purpose=blind-index;version=1" }
  ],
  "masking_profiles": [
    { "name": "performance-pan-mask-v1", "kid": "${K6_KID_PERFORMANCE}", "visible_first": 0, "visible_last": 4, "mask_char": "*", "min_len": 16, "max_len": 16 },
    { "name": "standard-ssn-mask-v1", "kid": "${K6_KID_STANDARD}", "visible_first": 0, "visible_last": 4, "mask_char": "*", "min_len": 9, "max_len": 9 },
    { "name": "high-assurance-bank-mask-v1", "kid": "${K6_KID_HIGH_ASSURANCE}", "visible_first": 0, "visible_last": 4, "mask_char": "*", "min_len": 12, "max_len": 12 },
    { "name": "long-term-account-mask-v1", "kid": "${K6_KID_LONG_TERM}", "visible_first": 0, "visible_last": 4, "mask_char": "*", "min_len": 12, "max_len": 12 }
  ],
  "commitment_profiles": [
    { "name": "performance-pan-commit-v1", "kid": "${K6_KID_PERFORMANCE}", "context": "tenant=k6;field=pan;purpose=commitment;version=1", "max_plaintext_len": 128, "opening_len": 32 },
    { "name": "standard-ssn-commit-v1", "kid": "${K6_KID_STANDARD}", "context": "tenant=k6;field=ssn;purpose=commitment;version=1", "max_plaintext_len": 128, "opening_len": 32 },
    { "name": "high-assurance-bank-commit-v1", "kid": "${K6_KID_HIGH_ASSURANCE}", "context": "tenant=k6;field=bank;purpose=commitment;version=1", "max_plaintext_len": 128, "opening_len": 32 },
    { "name": "long-term-account-commit-v1", "kid": "${K6_KID_LONG_TERM}", "context": "tenant=k6;field=account;purpose=commitment;version=1", "max_plaintext_len": 128, "opening_len": 32 }
  ],
  "sharing_profiles": [
    { "name": "performance-share-3of5-v1", "kid": "${K6_KID_PERFORMANCE}", "threshold": 3, "shares": 5, "max_secret_len": 128, "context": "tenant=k6;purpose=sharing;version=1" },
    { "name": "standard-share-3of5-v1", "kid": "${K6_KID_STANDARD}", "threshold": 3, "shares": 5, "max_secret_len": 128, "context": "tenant=k6;purpose=sharing;version=1" },
    { "name": "high-assurance-share-3of5-v1", "kid": "${K6_KID_HIGH_ASSURANCE}", "threshold": 3, "shares": 5, "max_secret_len": 128, "context": "tenant=k6;purpose=sharing;version=1" },
    { "name": "long-term-share-3of5-v1", "kid": "${K6_KID_LONG_TERM}", "threshold": 3, "shares": 5, "max_secret_len": 128, "context": "tenant=k6;purpose=sharing;version=1" }
  ]
}
JSON

(cd "${SITE_DIR}" && ./bin/vectis config sign --output json >/dev/null)

echo "Signed performance config with four KIDs and local profiles."
