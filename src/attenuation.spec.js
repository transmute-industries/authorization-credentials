const {
  JsonWebKey,
  JsonWebSignature,
} = require("@transmute/json-web-signature-2020");

const fs = require("fs");
const path = require("path");

const template = require("../examples/delegated-with-attentuation-template.json");

const createCapability = require("./lib/createCapability");
const verifyCapability = require("./lib/verifyCapability");
const createCapabilityInvocation = require("./lib/createCapabilityInvocation");
const verifyCapabilityInvocation = require("./lib/verifyCapabilityInvocation");

let attenuatedDelegation;
let attenuatedDelegationInvocation;
let suite;

let k0;
let k1;
let k2;

beforeAll(async () => {
  k0 = await JsonWebKey.from(require("../keys/k0.json"));
  k0.id = k0.controller + k0.id;
  k1 = await JsonWebKey.from(require("../keys/k1.json"));
  k1.id = k1.controller + k1.id;
});

describe("k0 can delegate with attenuation to k1", () => {
  it("can issue and verify", async () => {
    const suite = new JsonWebSignature({
      key: k0,
    });
    attenuatedDelegation = await createCapability(
      template,
      k0.controller,
      k1.controller,
      suite
    );
    const { verified } = await verifyCapability(attenuatedDelegation);
    expect(verified).toBe(true);

    fs.writeFileSync(
      path.resolve(
        __dirname,
        "../examples/delegated-with-attentuation-capability.json"
      ),
      JSON.stringify(attenuatedDelegation, null, 2)
    );
  });

  it("invoke and verify", async () => {
    suite = new JsonWebSignature({
      key: k1,
    });
    attenuatedDelegationInvocation = await createCapabilityInvocation(
      attenuatedDelegation,
      k1.controller,
      suite
    );
    const { verified } = await verifyCapabilityInvocation(
      attenuatedDelegationInvocation
    );
    expect(verified).toBe(true);

    fs.writeFileSync(
      path.resolve(
        __dirname,
        "../examples/delegated-with-attentuation-invocation.json"
      ),
      JSON.stringify(attenuatedDelegationInvocation, null, 2)
    );
  });
});
