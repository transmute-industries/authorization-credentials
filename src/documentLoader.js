const {
  documentLoaderFactory,
  contexts,
} = require("@transmute/jsonld-document-loader");

const { driver } = require("@transmute/did-key-web-crypto");

const golem = documentLoaderFactory.pluginFactory.build({
  contexts: {
    ...contexts.W3C_Decentralized_Identifiers,
    ...contexts.W3C_Verifiable_Credentials,
    ...contexts.W3ID_Security_Vocabulary,
  },
});

golem.addContext({
  "https://www.w3.org/2018/credentials/v2": require("../contexts/credentials-v2.json"),
});

golem.addResolver({
  "did:key:": {
    resolve: async (uri) => {
      const { didDocument } = await driver.resolve(uri, {
        accept: "application/did+json",
      });
      return didDocument;
    },
  },
  "http://example.com/zcaps/0": {
    resolve: async (uri) => {
      return require("../examples/root-capability.json");
    },
  },
  "http://example.com/zcaps/1": {
    resolve: async (uri) => {
      return require("../examples/delegated-with-attentuation-capability.json");
    },
  },
});

const documentLoader = golem.buildDocumentLoader();

module.exports = { documentLoader };
