const vcjs = require("@transmute/vc.js");
const { JsonWebSignature } = require("@transmute/json-web-signature-2020");

const { documentLoader } = require("../documentLoader");
const suite = new JsonWebSignature();

module.exports = verifyCapabilityInvocation = async (invocation) => {
  const verification = await vcjs.ld.verify({
    presentation: invocation,
    challenge: "123",
    suite,
    documentLoader,
  });
  return verification;
};
