const vcjs = require("@transmute/vc.js");
const { JsonWebSignature } = require("@transmute/json-web-signature-2020");

const suite = new JsonWebSignature();
const verifyCapability = require("./verifyCapability");

module.exports = verifyCapabilityInvocation = async (
  invocation,
  documentLoader = require("../documentLoader").documentLoader
) => {
  try {
    for (vc of invocation.verifiableCredential) {
      let verification = await verifyCapability(vc);
      if (verification.verified) {
        for (cap of vc.credentialSubject.authorization) {
          const zcap = (await documentLoader(cap.capability)).document;
          try {
            verification = await verifyCapability(zcap);
            if (!verification.verified) {
              throw new Error("Failed to verify capability: " + cap.capability);
            }
          } catch (e) {
            throw new Error("Failed to verify capability: " + cap.capability);
          }
        }
      }
    }
    const verification = await vcjs.ld.verify({
      presentation: invocation,
      challenge: "123",
      suite,
      documentLoader,
    });
    return verification;
  } catch (e) {
    return {
      verified: false,
      errors: [e.message],
    };
  }
};
