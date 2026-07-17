#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE_DIR="${SCRIPT_DIR}/site"

load_app_env() {
  local file="$1"
  while IFS='=' read -r key value; do
    [[ -z "${key}" || "${key}" == \#* ]] && continue
    printf -v "${key}" '%s' "${value}"
  done < "${file}"
}

if [[ ! -f "${SITE_DIR}/app.env" ]]; then
  echo "Missing app.env. Run: bash demo/local/create-keys.sh" >&2
  exit 1
fi

load_app_env "${SITE_DIR}/app.env"

cat > "${SITE_DIR}/config.json" <<JSON
{
  "version": "v1",
  "routes": [],
  "remote_routes": [],
  "permissions": [
    {
      "client": "${APP_CLIENT}",
      "apikey_hash": "${APP_APIKEY_HASH}",
      "status": "active",
      "permissions": [
        {
          "kid": "${LOCAL_KID}",
          "actions": [
            "fpe-encrypt",
            "fpe-decrypt",
            "token-encode",
            "token-decode",
            "mac-create",
            "mac-verify",
            "message",
            "sign"
          ]
        }
      ]
    }
  ],
  "fpe_profiles": [
    {
      "name": "credit-card-pan-v1",
      "fpe_version": "fpe-ff1-2025",
      "alphabet": "0123456789",
      "min_len": 16,
      "max_len": 16,
      "tweak_aad": "tenant=demo;field=credit_card_pan;version=1",
      "kid": "${LOCAL_KID}"
    },
    {
      "name": "ssn-decimal-v1",
      "fpe_version": "fpe-ff1-2025",
      "alphabet": "0123456789",
      "min_len": 9,
      "max_len": 9,
      "tweak_aad": "tenant=demo;field=ssn;version=1",
      "kid": "${LOCAL_KID}"
    },
    {
      "name": "identity-document-v1",
      "fpe_version": "fpe-ff1-2025",
      "alphabet": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "min_len": 6,
      "max_len": 32,
      "tweak_aad": "tenant=demo;field=identity_document;version=1",
      "kid": "${LOCAL_KID}"
    },
    {
      "name": "driver-license-v1",
      "fpe_version": "fpe-ff1-2025",
      "alphabet": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "min_len": 6,
      "max_len": 32,
      "tweak_aad": "tenant=demo;field=driver_license;version=1",
      "kid": "${LOCAL_KID}"
    },
    {
      "name": "bank-account-v1",
      "fpe_version": "fpe-ff1-2025",
      "alphabet": "0123456789",
      "min_len": 6,
      "max_len": 32,
      "tweak_aad": "tenant=demo;field=bank_account;version=1",
      "kid": "${LOCAL_KID}"
    },
    {
      "name": "payroll-number-v1",
      "fpe_version": "fpe-ff1-2025",
      "alphabet": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "min_len": 6,
      "max_len": 32,
      "tweak_aad": "tenant=demo;field=payroll_number;version=1",
      "kid": "${LOCAL_KID}"
    },
    {
      "name": "insurance-policy-v1",
      "fpe_version": "fpe-ff1-2025",
      "alphabet": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "min_len": 6,
      "max_len": 32,
      "tweak_aad": "tenant=demo;field=insurance_policy;version=1",
      "kid": "${LOCAL_KID}"
    }
  ],
  "tokenization_profiles": [
    {
      "name": "credit-card-token-v1",
      "tokenization_version": "token-random-v1",
      "kid": "${LOCAL_KID}",
      "token_prefix": "tok_card",
      "token_len": 32,
      "max_plaintext_len": 128
    },
    {
      "name": "ssn-token-v1",
      "tokenization_version": "token-random-v1",
      "kid": "${LOCAL_KID}",
      "token_prefix": "tok_ssn",
      "token_len": 32,
      "max_plaintext_len": 128
    },
    {
      "name": "identity-document-token-v1",
      "tokenization_version": "token-random-v1",
      "kid": "${LOCAL_KID}",
      "token_prefix": "tok_identity",
      "token_len": 32,
      "max_plaintext_len": 128
    },
    {
      "name": "driver-license-token-v1",
      "tokenization_version": "token-random-v1",
      "kid": "${LOCAL_KID}",
      "token_prefix": "tok_driver",
      "token_len": 32,
      "max_plaintext_len": 128
    },
    {
      "name": "bank-account-token-v1",
      "tokenization_version": "token-random-v1",
      "kid": "${LOCAL_KID}",
      "token_prefix": "tok_bank",
      "token_len": 32,
      "max_plaintext_len": 128
    },
    {
      "name": "payroll-number-token-v1",
      "tokenization_version": "token-random-v1",
      "kid": "${LOCAL_KID}",
      "token_prefix": "tok_payroll",
      "token_len": 32,
      "max_plaintext_len": 128
    },
    {
      "name": "insurance-policy-token-v1",
      "tokenization_version": "token-random-v1",
      "kid": "${LOCAL_KID}",
      "token_prefix": "tok_policy",
      "token_len": 32,
      "max_plaintext_len": 128
    }
  ],
  "mac_profiles": [
    {
      "name": "credit-card-pan-mac-v1",
      "kid": "${LOCAL_KID}",
      "context": "tenant=demo;field=credit_card_pan;purpose=blind_index;version=1"
    },
    {
      "name": "ssn-mac-v1",
      "kid": "${LOCAL_KID}",
      "context": "tenant=demo;field=ssn;purpose=blind_index;version=1"
    },
    {
      "name": "identity-document-mac-v1",
      "kid": "${LOCAL_KID}",
      "context": "tenant=demo;field=identity_document;purpose=blind_index;version=1"
    },
    {
      "name": "driver-license-mac-v1",
      "kid": "${LOCAL_KID}",
      "context": "tenant=demo;field=driver_license;purpose=blind_index;version=1"
    },
    {
      "name": "bank-account-mac-v1",
      "kid": "${LOCAL_KID}",
      "context": "tenant=demo;field=bank_account;purpose=blind_index;version=1"
    },
    {
      "name": "payroll-number-mac-v1",
      "kid": "${LOCAL_KID}",
      "context": "tenant=demo;field=payroll_number;purpose=blind_index;version=1"
    },
    {
      "name": "insurance-policy-mac-v1",
      "kid": "${LOCAL_KID}",
      "context": "tenant=demo;field=insurance_policy;purpose=blind_index;version=1"
    }
  ]
}
JSON

(cd "${SITE_DIR}" && ../bin/vectis config sign --output json >/dev/null)

echo "Signed local demo config:"
echo "  kid: ${LOCAL_KID}"
echo "  FPE profiles: 7"
echo "  tokenization profiles: 7"
echo "  MAC profiles: 7"
echo "Next: bash demo/local/start-vectis.sh"
