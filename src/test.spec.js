const fs = require("fs");
const path = require("path");

const {
  JsonWebKey,
  JsonWebSignature,
} = require("@transmute/json-web-signature-2020");
const vcjs = require("@transmute/vc.js");
const { documentLoader } = require("./documentLoader");

const credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/v2",
  ],
  id: "http://example.com/zcaps/0",
  type: ["VerifiableCredential", "AuthorizationCapability"],
  issuer: "did:example:123", // delegator
  issuanceDate: "2020-03-10T04:24:12.164Z",
  name: "Manage Vault Documents",
  description:
    "This capability grants a subject the ability to manage documents in a confidential datastore.",
  credentialSubject: {
    id: "did:example:456", // delegatee
    authorization: [
      {
        type: "https://w3id.org/security#capabilityInvocation",
        locations: ["https://example.com/edvs/123"],
        actions: [
          "https://w3id.org/security#vault.document.create",
          "https://w3id.org/security#vault.document.read",
          "https://w3id.org/security#vault.document.update",
          "https://w3id.org/security#vault.document.delete",
        ],
      },
    ],
  },
};

let rootCapability;
let delegatedByReference;
let invocatinOfDelegatinByReference;
let verificationOfInvocation;

it("can create manage vault document capability", async () => {
  const k0 = await JsonWebKey.from(require("../keys/k0.json"));
  k0.id = k0.controller + k0.id;
  const suite = new JsonWebSignature({
    key: k0,
    date: credential.issuanceDate,
  });
  rootCapability = await vcjs.ld.issue({
    credential: {
      ...credential,
      issuer: k0.controller,
      credentialSubject: {
        ...credential.credentialSubject,
        id: k0.controller,
      },
    },
    suite,
    documentLoader: async (uri) => {
      const res = await documentLoader(uri);
      return res;
    },
  });
  fs.writeFileSync(
    path.resolve(__dirname, "../examples/manage-vault-documents.json"),
    JSON.stringify(rootCapability, null, 2)
  );
});

it("can delegate by reference", async () => {
  const k0 = await JsonWebKey.from(require("../keys/k0.json"));
  k0.id = k0.controller + k0.id;
  const k1 = await JsonWebKey.from(require("../keys/k1.json"));
  const k2 = await JsonWebKey.from(require("../keys/k2.json"));
  const suite = new JsonWebSignature({
    key: k0,
    date: credential.issuanceDate,
  });
  delegatedByReference = await vcjs.ld.issue({
    credential: {
      ...credential,
      id: "http://example.com/zcaps/1",
      name: "Read Vault Documents",
      description:
        "This capability grants a subject the ability to read documents in a confidential datastore.",
      issuer: k0.controller,
      credentialSubject: [
        {
          id: k1.controller,
          authorization: [
            {
              capability: rootCapability.id,
              caveat: [
                {
                  actions: ["https://w3id.org/security#vault.document.create"],
                },
              ],
            },
          ],
        },
        {
          id: k2.controller,
          authorization: [
            {
              capability: rootCapability.id,
              caveat: [
                {
                  actions: ["https://w3id.org/security#vault.document.read"],
                },
              ],
            },
          ],
        },
      ],
    },
    suite,
    documentLoader: async (uri) => {
      const res = await documentLoader(uri);
      return res;
    },
  });
  fs.writeFileSync(
    path.resolve(
      __dirname,
      "../examples/manage-vault-documents-delegated-by-reference.json"
    ),
    JSON.stringify(delegatedByReference, null, 2)
  );
});

it("can invoke with presentation", async () => {
  const k1 = await JsonWebKey.from(require("../keys/k1.json"));
  k1.id = k1.controller + k1.id;
  const suite = new JsonWebSignature({
    key: k1,
    date: credential.issuanceDate,
  });

  const presentation = await vcjs.ld.createPresentation({
    verifiableCredential: delegatedByReference,
    holder: k1.id,
    documentLoader,
  });
  presentation["@context"].push("https://www.w3.org/2018/credentials/v2");
  presentation["type"].push("AuthorizationCapabilityInvocation");

  invocatinOfDelegatinByReference = await vcjs.ld.signPresentation({
    presentation,
    challenge: "123",
    suite,
    documentLoader: async (uri) => {
      const res = await documentLoader(uri);
      return res;
    },
  });
  fs.writeFileSync(
    path.resolve(
      __dirname,
      "../examples/invocation-of-delegated-by-reference.json"
    ),
    JSON.stringify(invocatinOfDelegatinByReference, null, 2)
  );
});

it("can verify invocation", async () => {
  const suite = new JsonWebSignature();
  verificationOfInvocation = await vcjs.ld.verify({
    presentation: invocatinOfDelegatinByReference,
    challenge: "123",
    suite,
    documentLoader: async (uri) => {
      const res = await documentLoader(uri);
      return res;
    },
  });
  fs.writeFileSync(
    path.resolve(__dirname, "../examples/verification-of-invocation.json"),
    JSON.stringify(verificationOfInvocation, null, 2)
  );
});
