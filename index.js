'use strict';

var createECDH = require('crypto').createECDH;

// secp256k1 generator point, ie, the public key for a private key of 1
var G = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

// node < 5 does not compute the public key in `setPrivateKey`
function nativeIsCorrect() {
	if (!createECDH) {
		return false;
	}
	try {
		var ecdh = createECDH('secp256k1');
		ecdh.setPrivateKey('01', 'hex');
		return ecdh.getPublicKey('hex') === G;
	} catch (e) {
		return false;
	}
}

/* istanbul ignore next */
module.exports = nativeIsCorrect() ? createECDH : require('./browser');
