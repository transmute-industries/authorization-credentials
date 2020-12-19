const vcjs = require("@transmute/vc.js");
const { documentLoader } = require("../documentLoader");

module.exports = createCapability = async (
  capability,
  delegator,
  invoker,
  suite
) => {
  return vcjs.ld.issue({
    credential: {
      ...capability,
      issuer: delegator,
      credentialSubject: {
        ...capability.credentialSubject,
        id: invoker,
      },
    },
    suite,
    documentLoader: async (uri) => {
      const res = await documentLoader(uri);
      return res;
    },
  });
};
