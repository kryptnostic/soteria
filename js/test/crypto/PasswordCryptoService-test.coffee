define [
  'require'
  'kryptnostic.cypher'
  'kryptnostic.password-crypto-service'
  'kryptnostic.abstract-crypto-service'
], (require) ->

  Cypher                = require 'kryptnostic.cypher'
  PasswordCryptoService = require 'kryptnostic.password-crypto-service'
  AbstractCryptoService = require 'kryptnostic.abstract-crypto-service'

  PASSWORD_1 = 'crom'
  PASSWORD_2 = 'demo'

  describe 'PasswordCryptoService', ->

    it 'should decrypt a known-good encrypted block', ->
      cryptoService = new PasswordCryptoService( Cypher.DEFAULT_CIPHER )
      blockCiphertext = {
        iv       : atob('YU6qbaCpNywwmVAbHCPOHw==')
        key      : atob('EEhKpvlkMwmp/iOLBC0Hdw==')
        salt     : atob('A5XYTHIdltr+Y+Cfl7KPNQ==')
        contents : atob('sz8C/u0Y3PLmCntjQTOXJRDcjItSP0EmPtAJuU2Q4pw=')
        tag      : atob('YP/DKVhyKJ/fWz0RMnX3gw==')
      }
      decrypted = cryptoService.decrypt(blockCiphertext, PASSWORD_2)
      expect(decrypted).toBe('|`9oÄ¯]Ù©¤UµQCôÓèUÒ~vk')

    it 'should decrypt an encrypted value', ->
      cryptoService = new PasswordCryptoService( Cypher.DEFAULT_CIPHER )
      value         = 'some text content here!'
      encrypted     = cryptoService.encrypt(value, PASSWORD_1)
      decrypted     = cryptoService.decrypt(encrypted, PASSWORD_1)
      expect(decrypted).toBe(value)

    it 'should derive a key correctly', ->
      cryptoService = new PasswordCryptoService( Cypher.DEFAULT_CIPHER )
      iter = AbstractCryptoService.BLOCK_CIPHER_ITERATIONS
      keySize = AbstractCryptoService.BLOCK_CIPHER_KEY_SIZE
      key = cryptoService._derive(PASSWORD_2, 'salt', iter, keySize)
      expect(btoa(key)).toBe('EX3hMH7vvRVCzE/HA2liSw==')
