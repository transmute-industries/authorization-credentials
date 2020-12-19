const vcjs = require("@transmute/vc.js");
const { documentLoader } = require("../documentLoader");

module.exports = createCapabilityInvocation = async (
  capability,
  invoker,
  suite
) => {
  const presentation = await vcjs.ld.createPresentation({
    verifiableCredential: capability,
    holder: invoker,
    documentLoader,
  });
  presentation["@context"].push("https://www.w3.org/2018/credentials/v2");
  presentation["type"].push("AuthorizationCapabilityInvocation");

  return vcjs.ld.signPresentation({
    presentation,
    challenge: "123",
    suite,
    documentLoader,
  });
};
