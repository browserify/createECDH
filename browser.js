'use strict';

var elliptic = require('elliptic');
var BN = require('bn.js');

var isArray = Array.isArray;

var aliases = {
	ed25519: {
		byteLength: 32,
		name: 'ed25519'
	},
	prime192v1: {
		byteLength: 24,
		name: 'p192'
	},
	prime256v1: {
		byteLength: 32,
		name: 'p256'
	},
	secp224r1: {
		byteLength: 28,
		name: 'p224'
	},
	secp256k1: {
		byteLength: 32,
		name: 'secp256k1'
	},
	secp384r1: {
		byteLength: 48,
		name: 'p384'
	},
	secp521r1: {
		byteLength: 66,
		name: 'p521'
	}
};

aliases.p224 = aliases.secp224r1;
aliases.secp256r1 = aliases.prime256v1;
aliases.p256 = aliases.prime256v1;
aliases.secp192r1 = aliases.prime192v1;
aliases.p192 = aliases.prime192v1;
aliases.p384 = aliases.secp384r1;
aliases.p521 = aliases.secp521r1;

function formatReturnValue(bn, enc, len) {
	var arr = isArray(bn) ? bn : bn.toArray();
	var buf = new Buffer(arr);
	if (len && buf.length < len) {
		var zeros = new Buffer(len - buf.length);
		zeros.fill(0);
		buf = Buffer.concat([zeros, buf]);
	}
	if (!enc) {
		return buf;
	}
	return buf.toString(enc);

}

function ECDH(curve) {
	this.curveType = aliases[curve];
	if (!this.curveType) {
		this.curveType = {
			name: curve
		};
	}
	this.curve = new elliptic.ec(this.curveType.name); // eslint-disable-line new-cap
	this.keys = void 0;
}

ECDH.prototype.generateKeys = function (enc, format) {
	this.keys = this.curve.genKeyPair();
	return this.getPublicKey(enc, format);
};

function validPublicKey(curve, pubBuf) {
	var key = curve.keyFromPublic(pubBuf);
	// rejects the point at infinity, points not on the curve, and points outside the prime-order subgroup
	var pub = key.getPublic();
	// elliptic's Montgomery ladder wrongly reports n * (x = 0) as infinity, so that low-order point passes `validate`
	if (!key.validate().result || (curve.curve.type === 'mont' && pub.getX().isZero())) {
		throw new Error('Public key is not valid for specified curve');
	}
	return pub;
}

ECDH.prototype.computeSecret = function (other, inenc, enc) {
	var otherBuf = Buffer.isBuffer(other) ? other : new Buffer(other, inenc || 'utf8');
	var otherPub = validPublicKey(this.curve, otherBuf);
	var out = this.keys.derive(otherPub);
	return formatReturnValue(out, enc, this.curveType.byteLength);
};

ECDH.prototype.getPublicKey = function (enc, format) {
	var key = this.keys.getPublic(format === 'compressed', true);
	if (format === 'hybrid') {
		if (key[key.length - 1] % 2) {
			key[0] = 7;
		} else {
			key[0] = 6;
		}
	}
	return formatReturnValue(key, enc);
};

ECDH.prototype.getPrivateKey = function (enc) {
	return formatReturnValue(this.keys.getPrivate(), enc);
};

ECDH.prototype.setPublicKey = function (pub, enc) {
	var pubBuf = Buffer.isBuffer(pub) ? pub : new Buffer(pub, enc || 'utf8');
	this.keys.pub = validPublicKey(this.curve, pubBuf);
	return this;
};

ECDH.prototype.setPrivateKey = function (priv, enc) {
	var privBuf = Buffer.isBuffer(priv) ? priv : new Buffer(priv, enc || 'utf8');

	var privHex = new BN(privBuf).toString(16);
	this.keys = this.curve.genKeyPair();
	this.keys._importPrivate(privHex);
	return this;
};

module.exports = function createECDH(curve) {
	return new ECDH(curve);
};
