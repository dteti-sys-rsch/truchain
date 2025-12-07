// tdlaas-utils.js
const { Utils } = require('@iota/sdk');

function generateMnemonic() {
  return Utils.generateMnemonic();
}

module.exports = { generateMnemonic };

