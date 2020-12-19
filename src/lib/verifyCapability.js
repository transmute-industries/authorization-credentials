const vcjs = require("@transmute/vc.js");
const { documentLoader } = require("../documentLoader");
const { JsonWebSignature } = require("@transmute/json-web-signature-2020");

const suite = new JsonWebSignature();

module.exports = verifyCapability = async (capability) => {
  return vcjs.ld.verifyCredential({
    credential: {
      ...capability,
    },
    suite,
    documentLoader,
  });
};
