var test = require('tape')
var nodeCrypto = require('./')
var myCrypto = require('./browser')

var mods = [
  'secp256k1',
  'secp224r1',
  'prime256v1',
  'prime192v1',
  'secp384r1',
  'secp521r1'
]

function run (i) {
  mods.forEach(function (mod) {
    test(mod + ' run ' + i + ' uncompressed', function (t) {
      t.plan(2)
      var dh1 = nodeCrypto(mod)
      dh1.generateKeys()
      var dh2 = myCrypto(mod)
      dh2.generateKeys()
      var pubk1 = dh1.getPublicKey()
      var pubk2 = dh2.getPublicKey()
      t.notEquals(pubk1.toString('hex'), pubk2.toString('hex'), 'diff public keys')
      var pub1 = dh1.computeSecret(pubk2).toString('hex')
      var pub2 = dh2.computeSecret(pubk1).toString('hex')
      t.equals(pub1, pub2, 'equal secrets')
    })
    test(mod + ' run ' + i + ' compressed', function (t) {
      t.plan(2)
      var dh1 = nodeCrypto(mod)
      dh1.generateKeys()
      var dh2 = myCrypto(mod)
      dh2.generateKeys()
      var pubk1 = dh1.getPublicKey(null, 'compressed')
      var pubk2 = dh2.getPublicKey(null, 'compressed')
      t.notEquals(pubk1.toString('hex'), pubk2.toString('hex'), 'diff public keys')
      var pub1 = dh1.computeSecret(pubk2).toString('hex')
      var pub2 = dh2.computeSecret(pubk1).toString('hex')
      t.equals(pub1, pub2, 'equal secrets')
    })
    test(mod + ' run ' + i + ' set stuff', function (t) {
      t.plan(5)
      var dh1 = nodeCrypto(mod)
      var dh2 = myCrypto(mod)
      dh1.generateKeys()
      dh2.generateKeys()
      dh1.setPrivateKey(dh2.getPrivateKey())
      dh1.setPublicKey(dh2.getPublicKey())
      var priv1 = dh1.getPrivateKey('hex')
      var priv2 = dh2.getPrivateKey('hex')
      t.equals(priv1, priv2, 'same private key')
      var pubk1 = dh1.getPublicKey()
      var pubk2 = dh2.getPublicKey()
      t.equals(pubk1.toString('hex'), pubk2.toString('hex'), 'same public keys, uncompressed')
      t.equals(dh1.getPublicKey('hex', 'compressed'), dh2.getPublicKey('hex', 'compressed'), 'same public keys compressed')
      t.equals(dh1.getPublicKey('hex', 'hybrid'), dh2.getPublicKey('hex', 'hybrid'), 'same public keys hybrid')
      var pub1 = dh1.computeSecret(pubk2).toString('hex')
      var pub2 = dh2.computeSecret(pubk1).toString('hex')
      t.equals(pub1, pub2, 'equal secrets')
    })
    test(mod + ' run ' + i + ' new way to set stuff', function (t) {
      t.plan(5)
      var dh1 = myCrypto(mod)
      var dh2 = nodeCrypto(mod)
      dh2.generateKeys()
      dh1.setPrivateKey(dh2.getPrivateKey())
      var priv1 = dh1.getPrivateKey('hex')
      var priv2 = dh2.getPrivateKey('hex')
      t.equals(priv1, priv2, 'same private key')
      var pubk1 = dh1.getPublicKey()
      var pubk2 = dh2.getPublicKey()
      t.equals(pubk1.toString('hex'), pubk2.toString('hex'), 'same public keys, uncompressed')
      t.equals(dh1.getPublicKey('hex', 'compressed'), dh2.getPublicKey('hex', 'compressed'), 'same public keys compressed')
      t.equals(dh1.getPublicKey('hex', 'hybrid'), dh2.getPublicKey('hex', 'hybrid'), 'same public keys hybrid')
      var pub1 = dh1.computeSecret(pubk2).toString('hex')
      var pub2 = dh2.computeSecret(pubk1).toString('hex')
      t.equals(pub1, pub2, 'equal secrets')
    })
  })
}
apitests('api tests for my crypto', myCrypto)
apitests('api tests for node crypto', nodeCrypto)
function apitests (name, crypto) {
  test(name, function (t) {
    t.test('check about regenerating keys', function (t) {
      t.plan(2)
      var dh1 = crypto('secp256k1')
      var dh2 = crypto('secp256k1')
      dh1.generateKeys()
      dh2.generateKeys()
      var pub = dh1.getPublicKey('hex')
      var priv = dh1.getPrivateKey('hex')
      dh1.setPrivateKey(dh2.getPrivateKey())
      t.notEquals(dh1.getPrivateKey('hex'), priv, 'private keys not equal')
      t.notEquals(dh1.getPublicKey('hex'), pub, 'public keys not equal')
    })
    t.test('set private keys without generating them', function (t) {
      t.plan(1)
      var dh1 = crypto('secp256k1')
      var dh2 = crypto('secp256k1')
      dh2.generateKeys()
      dh1.setPrivateKey(dh2.getPrivateKey())
      t.equals(dh1.getPublicKey('hex'), dh1.getPublicKey('hex'), 'equal public keys')
    })
  })
}
var i = 0
while (++i < 20) {
  run(i)
}
