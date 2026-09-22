#!/usr/bin/env node
// Re-keys a captured 1Password fixture from the account's real credentials to made-up ones.
//
// The master keyset is the only thing sealed with the password-derived key. Every other key
// hangs off its symmetric key, which stays the same, so vault keys and items need no change.
// The envelope keeps its IV and the file keeps its formatting, so the diff is the re-sealed
// `data` plus the fields that name the account's owner.
//
//   node reencrypt.mjs keysets --old-email … --old-password … --old-secret-key … account/keysets-response.json
//   node reencrypt.mjs account --old-email … --old-password … --old-secret-key … account/account-response.json
//
// The `--new-*` options default to the credentials replay.rs uses.

import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import prettier from "prettier";
import {
  deriveMasterKey,
  openEnvelope,
  parseSecretKey,
  sealEnvelope,
} from "./onepassword-crypto.mjs";

const TEST_CREDENTIALS = {
  email: "user@example.com",
  password: "password",
  secretKey: "A3-ABCDEF-GHJKLM-NPQRS-TVWXY-Z2345-6789A",
};
const TEST_NAME = { firstName: "Example", lastName: "User", name: "Example User" };
const TEST_INVITE_SECRET = "ABCDEFGHJKLMNPQRSTVWXYZ234";

// Reseals every master keyset's symmetric key. The newest master keyset carries the KDF
// parameters, and the key derived from them opens every one, as in keychain.rs.
function rekeyMasterKeysets(keysets, oldCredentials, newCredentials) {
  const masters = keysets.filter((keyset) => keyset.encryptedBy === "mp");
  if (masters.length === 0) {
    throw new Error("no master keyset");
  }
  const newest = masters.reduce((a, b) => (b.sn > a.sn ? b : a)).encSymKey;
  const oldMasterKey = deriveMasterKey(oldCredentials, newest);
  const newMasterKey = deriveMasterKey(newCredentials, newest);
  for (const { encSymKey } of masters) {
    const symmetricKey = openEnvelope(oldMasterKey, encSymKey);
    encSymKey.data = sealEnvelope(newMasterKey, encSymKey, symmetricKey);
  }
}

// `v1/account/keysets`.
function reencryptKeysets(json, oldCredentials, newCredentials) {
  if (!Array.isArray(json.keysets)) {
    throw new Error("not a keysets response");
  }
  rekeyMasterKeysets(json.keysets, oldCredentials, newCredentials);
}

// `v1/account`: the embedded master keyset plus everything that names the account's owner.
function reencryptAccount(json, oldCredentials, newCredentials) {
  const { me } = json;
  if (!Array.isArray(me?.keysets)) {
    throw new Error("not an account response");
  }
  rekeyMasterKeysets(me.keysets, oldCredentials, newCredentials);

  // An individual account is named after its owner.
  if (json.name === me.name) {
    json.name = TEST_NAME.name;
  }
  for (const user of [me, ...json.users.filter((user) => user.uuid === me.uuid)]) {
    Object.assign(user, { email: newCredentials.email, ...TEST_NAME });
  }
  const { format, uuid } = parseSecretKey(newCredentials.secretKey);
  me.accountKeyFormat = format;
  me.accountKeyUuid = uuid;
  json.invite.inviteSecret = TEST_INVITE_SECRET;
}

const FIXTURES = { keysets: reencryptKeysets, account: reencryptAccount };

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "old-email": { type: "string" },
    "old-password": { type: "string" },
    "old-secret-key": { type: "string" },
    "new-email": { type: "string", default: TEST_CREDENTIALS.email },
    "new-password": { type: "string", default: TEST_CREDENTIALS.password },
    "new-secret-key": { type: "string", default: TEST_CREDENTIALS.secretKey },
  },
});
const credentials = (age) => ({
  email: values[`${age}-email`],
  password: values[`${age}-password`],
  secretKey: values[`${age}-secret-key`],
});

const [kind, file] = positionals;
const reencrypt = FIXTURES[kind];
const old = credentials("old");
if (!reencrypt || !file || !old.email || !old.password || !old.secretKey) {
  console.error(
    `usage: reencrypt.mjs <${Object.keys(FIXTURES).join("|")}> --old-email … --old-password …` +
      " --old-secret-key … [--new-email …] [--new-password …] [--new-secret-key …] <fixture.json>",
  );
  process.exit(2);
}

const json = JSON.parse(readFileSync(file, "utf8"));
reencrypt(json, old, credentials("new"));
// The captures are prettier formatted, so reformatting keeps the diff to the changed values.
const options = { ...(await prettier.resolveConfig(file)), parser: "json" };
writeFileSync(file, await prettier.format(JSON.stringify(json, null, 2), options));
