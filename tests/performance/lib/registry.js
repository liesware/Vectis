export function validateCatalog(value) {
  const require = (condition) => { if (!condition) throw new Error("invalid performance catalog"); };
  require(value && value.version === 1 && Array.isArray(value.profiles) && value.profiles.length > 0 &&
    Array.isArray(value.targets) && value.targets.length > 0);
  const unique = (entries, field) => new Set(entries.map((entry) => entry[field])).size === entries.length;
  for (const profile of value.profiles) {
    require(profile && ["name", "slug", "kid_env"].every((key) => typeof profile[key] === "string" && profile[key]));
  }
  require(["name", "slug", "kid_env"].every((key) => unique(value.profiles, key)));
  const families = new Map();
  for (const target of value.targets) {
    require(target && ["name", "family"].every((key) => typeof target[key] === "string" && target[key]) &&
      target.name !== "all");
    require(["batch", "subject", "authenticated"].every((key) => typeof target[key] === "boolean"));
    require(Array.isArray(target.operations) && target.operations.length > 0 &&
      target.operations.every((op) => typeof op === "string" && op && op !== "flow") &&
      new Set(target.operations).size === target.operations.length);
    require(target.name === target.family + (target.batch ? "-batch" : ""));
    const signature = JSON.stringify([target.subject, target.authenticated, target.operations]);
    require(!families.has(target.family) || families.get(target.family) === signature);
    families.set(target.family, signature);
  }
  require(unique(value.targets, "name") &&
    new Set(value.targets.map((target) => target.name.replace(/-/g, "_"))).size === value.targets.length);
  return value;
}

export const CATALOG = validateCatalog(JSON.parse(open("../catalog.json")));
export const PROFILES = CATALOG.profiles.map((profile) => profile.name);
export const TARGETS = CATALOG.targets.map((target) => target.name);
const definitions = new Map(CATALOG.targets.map((target) => [target.name, target]));

export function validateRunners(runners) {
  const families = new Set(CATALOG.targets.map((target) => target.family));
  if (Object.keys(runners).length !== families.size ||
      [...families].some((family) => typeof runners[family] !== "function")) {
    throw new Error("performance catalog and flow registry disagree");
  }
}

export function selectCases(target, subject = false, authenticated = false, batchSize = 3) {
  if (target !== "all" && !definitions.has(target)) throw new Error("unknown performance target");
  if (subject && !definitions.get(target)?.subject) throw new Error("incompatible subject option");
  if (authenticated && !definitions.get(target)?.authenticated) throw new Error("incompatible authentication option");
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 128) throw new Error("invalid batch size");
  const cases = [];
  for (const name of target === "all" ? TARGETS : [target]) {
    const spec = definitions.get(name);
    for (const scope of target === "all" && spec.subject ? [false, true] : [subject]) {
      for (const auth of target === "all" && spec.authenticated ? [false, true] : [authenticated]) {
        cases.push({ target: name, subject: scope, authenticated: auth,
          batchSize: spec.batch ? batchSize : 1,
          id: `${name.replace(/-/g, "_")}_${scope ? "stored" : "none"}_${auth ? "auth" : "legacy"}` });
      }
    }
  }
  return cases;
}

export function definition(test) {
  return definitions.get(test.target);
}

export function operations(test) {
  const spec = definition(test);
  return spec.operations.map((name) => `${spec.family.replace(/-/g, "_")}_${name}${spec.batch ? "_batch" : ""}`);
}
