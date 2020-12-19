const {
  JsonWebKey,
  JsonWebSignature,
} = require("@transmute/json-web-signature-2020");

const fs = require("fs");
const path = require("path");

const template = require("../examples/root-capability-template.json");

const createCapability = require("./lib/createCapability");
const verifyCapability = require("./lib/verifyCapability");
const createCapabilityInvocation = require("./lib/createCapabilityInvocation");
const verifyCapabilityInvocation = require("./lib/verifyCapabilityInvocation");

let k0;
let rootCapability;
let rootCapabilityInvocation;
let suite;

beforeAll(async () => {
  k0 = await JsonWebKey.from(require("../keys/k0.json"));
  k0.id = k0.controller + k0.id;
  suite = new JsonWebSignature({
    key: k0,
  });
});

describe("k0 can create root capability", () => {
  it("can issue and verify", async () => {
    rootCapability = await createCapability(
      template,
      k0.controller,
      k0.controller,
      suite
    );
    const { verified } = await verifyCapability(rootCapability);
    expect(verified).toBe(true);

    fs.writeFileSync(
      path.resolve(__dirname, "../examples/root-capability.json"),
      JSON.stringify(rootCapability, null, 2)
    );
  });

  it("cannot verify tampered capabilities", async () => {
    let rootCapability2 = await createCapability(
      template,
      k0.controller,
      k0.controller,
      suite
    );
    rootCapability2.credentialSubject.id = "did:example:123";
    const { verified } = await verifyCapability(rootCapability2);
    expect(verified).toBe(false);
  });

  it("invoke and verify", async () => {
    rootCapabilityInvocation = await createCapabilityInvocation(
      rootCapability,
      k0.controller,
      suite
    );
    const { verified } = await verifyCapabilityInvocation(
      rootCapabilityInvocation
    );
    expect(verified).toBe(true);

    fs.writeFileSync(
      path.resolve(__dirname, "../examples/root-capability-invocation.json"),
      JSON.stringify(rootCapabilityInvocation, null, 2)
    );
  });

  it("cannot verify tampered invocations", async () => {
    const rootCapabilityInvocation2 = await createCapabilityInvocation(
      rootCapability,
      k0.controller,
      suite
    );
    rootCapabilityInvocation2.holder = "did:example:123";
    const { verified } = await verifyCapabilityInvocation(
      rootCapabilityInvocation2
    );
    expect(verified).toBe(false);
  });
});
