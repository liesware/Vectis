import http from "k6/http";
import { check, fail } from "k6";
import crypto from "k6/crypto";

export const options = {
  thresholds: {
    checks: ["rate>0.99"],
    http_req_failed: ["rate<0.01"],
  },
};

const DEFAULT_BASE_URL = "http://127.0.0.1:3000";
const DEFAULT_CONFIG_PATH = "config.json";
const DEFAULT_PROFILE = "hybrid-performance-v1";
const SIGN_MESSAGE = "k6 performance sign message";

const envFile = parseEnvFile(readEnvFile().text);
const configFile = readConfigFile(configValue("VECTIS_CONFIG_PATH", DEFAULT_CONFIG_PATH));

function readEnvFile() {
  try {
    return {
      path: ".env",
      text: open(".env"),
    };
  } catch (_) {
    // Try the repository root when k6 resolves paths from this script.
  }

  try {
    return {
      path: "../../.env",
      text: open("../../.env"),
    };
  } catch (_) {
    // .env is optional; real environment variables can provide the values.
  }

  return {
    path: "",
    text: "",
  };
}

function readConfigFile(path) {
  if (path === DEFAULT_CONFIG_PATH) {
    try {
      return {
        path: DEFAULT_CONFIG_PATH,
        text: open("config.json"),
      };
    } catch (_) {
      // Try the repository root when k6 resolves paths from this script.
    }

    try {
      return {
        path: `../../${DEFAULT_CONFIG_PATH}`,
        text: open("../../config.json"),
      };
    } catch (_) {
      return {
        path: "",
        text: "",
      };
    }
  }

  return {
    path: "",
    text: "",
  };
}

function parseEnvFile(text) {
  const values = {};

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const index = line.indexOf("=");
    if (index <= 0) {
      continue;
    }

    const key = line.slice(0, index).trim().replace(/^export\s+/, "");
    let value = line.slice(index + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    values[key] = value;
  }

  return values;
}

function configValue(name, fallback = "") {
  if (__ENV[name] !== undefined && __ENV[name] !== "") {
    return __ENV[name];
  }
  if (envFile[name] !== undefined && envFile[name] !== "") {
    return envFile[name];
  }
  return fallback;
}

function baseUrl() {
  return configValue("VECTIS_API_URL", DEFAULT_BASE_URL).replace(/\/+$/, "");
}

function apiKey() {
  return configValue("VECTIS_APIKEY");
}

function configPath() {
  return configValue("VECTIS_CONFIG_PATH", DEFAULT_CONFIG_PATH);
}

function keyProfile() {
  return configValue("VECTIS_DEFAULT_CRYPTO_PROFILE", DEFAULT_PROFILE);
}

function loadConfig() {
  const path = configPath();

  if (!configFile.text) {
    fail(
      `could not read ${path}; k6 can only bundle the default config.json path in this script`,
    );
  }

  try {
    return JSON.parse(configFile.text);
  } catch (err) {
    fail(`${configFile.path} must be valid JSON: ${err}`);
  }

  return {};
}

function selectRemoteRoute(config) {
  const routes = Array.isArray(config.remote_routes) ? config.remote_routes : [];
  const route = routes.find(
    (item) =>
      item &&
      item.status === "active" &&
      typeof item.remote_kid === "string" &&
      item.remote_kid.length > 0 &&
      item.public_keys &&
      Array.isArray(item.allowed_local_kids) &&
      item.allowed_local_kids.includes("*"),
  );

  if (!route) {
    fail(
      `${configPath()} must contain an active remote_routes entry with public_keys and allowed_local_kids ["*"]`,
    );
  }

  return route;
}

function selectMessageSenderKid(config, remoteRoute, createdKid) {
  const localRoutes = Array.isArray(config.routes) ? config.routes : [];
  const localKids = localRoutes
    .map((route) => route && route.kid)
    .filter((kid) => typeof kid === "string" && kid.length > 0);
  const allowedKids = Array.isArray(remoteRoute.allowed_local_kids)
    ? remoteRoute.allowed_local_kids
    : [];

  const explicitAllowedKid = allowedKids.find(
    (kid) => kid !== "*" && localKids.includes(kid),
  );
  if (explicitAllowedKid) {
    return explicitAllowedKid;
  }

  if (allowedKids.includes("*") && localKids.length > 0) {
    return localKids[0];
  }

  if (allowedKids.includes("*")) {
    return createdKid;
  }

  fail(
    `${configPath()} does not contain a local sender KID allowed by remote route ${remoteRoute.name || remoteRoute.remote_kid}`,
  );

  return "";
}

function truncateKid(kid) {
  if (!kid || kid.length <= 16) {
    return kid || "";
  }
  return `${kid.slice(0, 8)}...${kid.slice(-8)}`;
}

function requestIdHeader(response) {
  for (const name in response.headers) {
    if (name.toLowerCase() === "x-request-id") {
      return response.headers[name];
    }
  }
  return "";
}

function publicHeaders() {
  return {
    "Content-Type": "application/json",
  };
}

function authHeaders() {
  return {
    "Content-Type": "application/json",
    "X-API-Key": apiKey(),
  };
}

function parseJson(response, label) {
  try {
    return JSON.parse(response.body || "{}");
  } catch (err) {
    fail(`${label} returned invalid JSON: ${err}`);
  }

  return {};
}

function checkedGet(path, label, authenticated = false) {
  const response = http.get(`${baseUrl()}${path}`, {
    headers: authenticated ? authHeaders() : publicHeaders(),
  });

  check(response, {
    [`${label}: status 200`]: (res) => res.status === 200,
    [`${label}: X-Request-Id present`]: (res) => requestIdHeader(res) !== "",
  });

  if (response.status !== 200) {
    fail(`${label} failed with HTTP ${response.status}: ${response.body}`);
  }

  return parseJson(response, label);
}

function checkedPost(path, body, label, authenticated = true) {
  const response = http.post(`${baseUrl()}${path}`, JSON.stringify(body), {
    headers: authenticated ? authHeaders() : publicHeaders(),
  });

  check(response, {
    [`${label}: status 200`]: (res) => res.status === 200,
    [`${label}: X-Request-Id present`]: (res) => requestIdHeader(res) !== "",
  });

  if (response.status !== 200) {
    fail(`${label} failed with HTTP ${response.status}: ${response.body}`);
  }

  return parseJson(response, label);
}

function createKey() {
  const response = checkedPost(
    "/keys",
    {
      tag: "k6-performance",
      profile: keyProfile(),
    },
    "POST /keys",
  );

  check(response, {
    "POST /keys: id present": (body) =>
      typeof body.id === "string" && body.id.length > 0,
  });

  if (typeof response.id !== "string" || response.id.length === 0) {
    fail("POST /keys did not return id");
  }

  return response.id;
}

export function setup() {
  if (!baseUrl()) {
    fail("VECTIS_API_URL is required");
  }
  if (!apiKey()) {
    fail("VECTIS_APIKEY is required");
  }

  const config = loadConfig();
  const route = selectRemoteRoute(config);

  checkedGet("/healthz/startup", "GET /healthz/startup");
  checkedGet("/healthz/live", "GET /healthz/live");
  const ready = checkedGet("/healthz/ready", "GET /healthz/ready");
  check(ready, {
    "GET /healthz/ready: ready": (body) => body.status === "ready",
  });

  const createdKid = createKey();
  const messageSenderKid = selectMessageSenderKid(config, route, createdKid);

  console.log(
    `k6 vectis performance: base_url=${baseUrl()} created_kid=${truncateKid(
      createdKid,
    )} message_sender_kid=${truncateKid(messageSenderKid)} recipient_kid=${truncateKid(
      route.remote_kid,
    )} route=${route.name || "unnamed"}`,
  );

  return {
    createdKid,
    messageSenderKid,
    recipientKid: route.remote_kid,
  };
}

export default function (data) {
  checkedGet("/healthz/live", "GET /healthz/live");
  checkedGet("/healthz/ready", "GET /healthz/ready");

  const publicKeys = checkedGet(`/pub/${data.createdKid}`, "GET /pub/{kid}");
  check(publicKeys, {
    "GET /pub/{kid}: keys present": (body) =>
      body.keys &&
      body.keys.eddsa &&
      body.keys.xecdh &&
      body.keys["ml-dsa"] &&
      body.keys["ml-kem"],
  });

  const selfTest = checkedGet(
    `/self-test/keys/${data.createdKid}`,
    "GET /self-test/keys/{kid}",
    true,
  );
  check(selfTest, {
    "GET /self-test/keys/{kid}: components valid": (body) =>
      body.symmetric &&
      body.symmetric.valid === true &&
      body.eddsa &&
      body.eddsa.valid === true &&
      body.xecdh &&
      body.xecdh.valid === true &&
      body["ml-dsa"] &&
      body["ml-dsa"].valid === true &&
      body["ml-kem"] &&
      body["ml-kem"].valid === true,
  });

  const messageHash = crypto.sha256(SIGN_MESSAGE, "hex");
  const signed = checkedPost(
    `/sign/${data.createdKid}`,
    {
      message_hash: {
        alg: "SHA-256",
        hex: messageHash,
      },
    },
    "POST /sign/{kid}",
  );
  check(signed, {
    "POST /sign/{kid}: payload present": (body) => Boolean(body.payload),
    "POST /sign/{kid}: signatures present": (body) => Boolean(body.signatures),
  });

  const verification = checkedPost(
    "/sign/verification",
    signed,
    "POST /sign/verification",
  );
  check(verification, {
    "POST /sign/verification: valid ok": (body) => body.valid === "ok",
  });

  const plaintext = `k6 internal message ${__VU}-${__ITER}`;
  const encrypted = checkedPost(
    `/message/internal/encrypt/${data.createdKid}`,
    {
      plaintext,
    },
    "POST /message/internal/encrypt/{kid}",
  );
  check(encrypted, {
    "POST /message/internal/encrypt/{kid}: message present": (body) =>
      Boolean(body.message),
  });

  const decrypted = checkedPost(
    "/message/internal/decrypt",
    encrypted,
    "POST /message/internal/decrypt",
  );
  check(decrypted, {
    "POST /message/internal/decrypt: plaintext matches": (body) =>
      body.plaintext === plaintext,
  });

  const message = checkedPost(
    `/message/${data.messageSenderKid}`,
    {
      recipient_kid: data.recipientKid,
      message: "k6 performance message",
    },
    "POST /message/{kid}",
  );
  check(message, {
    "POST /message/{kid}: message valid": (body) =>
      body.message && body.message.valid === true,
  });
}
