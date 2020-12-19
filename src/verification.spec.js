const { JsonWebKey } = require("@transmute/json-web-signature-2020");

const { documentLoader } = require("./documentLoader");
const verifyCapabilityInvocation = require("./lib/verifyCapabilityInvocation");

let k0;
let k1;

beforeAll(async () => {
  k0 = await JsonWebKey.from(require("../keys/k0.json"));
  k0.id = k0.controller + k0.id;
  k1 = await JsonWebKey.from(require("../keys/k1.json"));
  k1.id = k1.controller + k1.id;
});

it(`http://example.com/zcaps/0 describes k0's ability to manage documents`, async () => {
  const cap0 = (await documentLoader("http://example.com/zcaps/0")).document;
  expect(cap0.issuer).toBe(k0.controller);
  expect(cap0.credentialSubject.id).toBe(k0.controller);
  expect(cap0.credentialSubject.authorization[0].actions).toEqual([
    "https://w3id.org/security#vault.document.create",
    "https://w3id.org/security#vault.document.read",
    "https://w3id.org/security#vault.document.update",
    "https://w3id.org/security#vault.document.delete",
  ]);
});

it(`http://example.com/zcaps/1 describes k0's delegation with attentuation to k1`, async () => {
  const cap0 = (await documentLoader("http://example.com/zcaps/1")).document;
  expect(cap0.issuer).toBe(k0.controller);
  expect(cap0.credentialSubject.id).toBe(k1.controller);

  expect(cap0.credentialSubject.authorization[0].capability).toBe(
    "http://example.com/zcaps/0"
  );
  expect(cap0.credentialSubject.authorization[0].caveat[0].actions).toEqual([
    "https://w3id.org/security#vault.document.read",
  ]);
});

it(`k1 cannot invoke zcaps/1 in zcaps/0 in not verifiable `, async () => {
  const { verified, errors } = await verifyCapabilityInvocation(
    require("../examples/delegated-with-attentuation-invocation.json"),
    (uri) => {
      if (uri === "http://example.com/zcaps/0") {
        return { document: {} };
      } else {
        return documentLoader(uri);
      }
    }
  );
  expect(verified).toBe(false);
  expect(errors).toEqual([
    "Failed to verify capability: http://example.com/zcaps/0",
  ]);
});
