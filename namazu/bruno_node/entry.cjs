// Build-only entry. The generated parser.cjs contains the official MIT parser.
module.exports = {
  request: require('@usebruno/lang/v2/src/bruToJson'),
  collection: require('@usebruno/lang/v2/src/collectionBruToJson'),
  environment: require('@usebruno/lang/v2/src/envToJson'),
  requestText: require('@usebruno/lang/v2/src/jsonToBru'),
  environmentText: require('@usebruno/lang/v2/src/jsonToEnv'),
};
