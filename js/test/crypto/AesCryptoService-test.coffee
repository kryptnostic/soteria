define [
  'require',
  'forge',
  'kryptnostic.cypher',
  'kryptnostic.aes-crypto-service',
  'kryptnostic.abstract-crypto-service',
  'kryptnostic.block-ciphertext'
], (require) ->

  AesCryptoService      = require 'kryptnostic.aes-crypto-service'
  AbstractCryptoService = require 'kryptnostic.abstract-crypto-service'
  Forge                 = require 'forge'
  Cypher                = require 'kryptnostic.cypher'
  BlockCiphertext       = require 'kryptnostic.block-ciphertext'

  CYPHER = Cypher.DEFAULT_CIPHER
  cryptoService = undefined

  beforeEach ->
    key           = Forge.random.getBytesSync(AbstractCryptoService.BLOCK_CIPHER_KEY_SIZE)
    cryptoService = new AesCryptoService(CYPHER, key)

  describe 'AesCryptoService', ->

    describe '#BLOCK_CIPHER_KEY_SIZE', ->

      it 'should be 16 bytes', ->
        expect(AbstractCryptoService.BLOCK_CIPHER_KEY_SIZE).toBe(16)

    describe '#encrypt', ->

      it 'should produce a block ciphertext', ->
        plaintext       = 'convert to block ciphertext'
        blockCiphertext = cryptoService.encrypt(plaintext)
        expect(blockCiphertext.constructor.name).toBe('BlockCiphertext')
        expect(blockCiphertext.iv).toBeDefined()
        expect(blockCiphertext.contents).toBeDefined()

      it 'should produce an initialization vector in base 64 with a binary length of 16 bytes', ->
        plaintext       = 'convert to block ciphertext'
        blockCiphertext = cryptoService.encrypt(plaintext)
        byteCount       = Forge.util.createBuffer(atob(blockCiphertext.iv), 'raw').length()
        expect(byteCount).toBe(16)

    describe '#decrypt', ->

      it 'should be able to decrypt what it encrypts', ->
        plaintext       = 'sensitive data'
        blockCiphertext = cryptoService.encrypt(plaintext)
        decrypted       = cryptoService.decrypt(blockCiphertext)
        expect(decrypted).toBe(plaintext)

      it 'should decrypt a known value with fixed inputs', ->
        plaintext       = 'convert to block ciphertext'
        key             = atob('DtPJS+lb5ujWvab3Man+sg==')
        cryptoService   = new AesCryptoService(CYPHER, key)
        blockCiphertext = new BlockCiphertext {
          iv       :'plLEhEuTp6kb3b/UGsseeQ=='
          salt     :'SRkDJNLCNfK8yIL60bjZ6Q=='
          contents :'JKjSbpD3OFR2+HcIwL1jCqWZAMZeXoExbgiT'
          tag      :'RAop49ZFXy11aqXHmmnrEA=='
        }
        expect(cryptoService.decrypt(blockCiphertext)).toBe(plaintext)

