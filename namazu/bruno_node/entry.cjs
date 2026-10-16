// Build-only entry. The generated parser.cjs contains the official MIT parser.
module.exports = {
  request: require('@usebruno/lang/v2/src/bruToJson'),
  collection: require('@usebruno/lang/v2/src/collectionBruToJson'),
  environment: require('@usebruno/lang/v2/src/envToJson'),
  requestText: require('@usebruno/lang/v2/src/jsonToBru'),
  environmentText: require('@usebruno/lang/v2/src/jsonToEnv'),
  yamlRequest: require('@usebruno/filestore/src/formats/yml/parseItem.ts').default,
  yamlCollection: require('@usebruno/filestore/src/formats/yml/parseCollection.ts').default,
  yamlFolder: require('@usebruno/filestore/src/formats/yml/parseFolder.ts').default,
  yamlEnvironment: require('@usebruno/filestore/src/formats/yml/parseEnvironment.ts').default,
  resolveEnvironment: require('@usebruno/common/utils').resolveEnvironmentInheritance,
  sortLists: lists => lists.map(require('@usebruno/common').sortByNameThenSequence),
};
