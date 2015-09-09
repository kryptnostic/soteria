define [
  'require'
  'kryptnostic.cypher'
  'kryptnostic.abstract-crypto-service'
], (require) ->

  AbstractCryptoService = require 'kryptnostic.abstract-crypto-service'
  Cypher                = require 'kryptnostic.cypher'

  describe 'AbstractCryptoService', ->

    cryptoService = new AbstractCryptoService( Cypher.DEFAULT_CIPHER )

    it 'should decrypt known-good values correctly', ->
      iv         = atob('YU6qbaCpNywwmVAbHCPOHw==')
      key        = atob('EEhKpvlkMwmp/iOLBC0Hdw==')
      ciphertext = atob('sz8C/u0Y3PLmCntjQTOXJRDcjItSP0EmPtAJuU2Q4pw=')
      tag        = atob('YP/DKVhyKJ/fWz0RMnX3gw==')
      decrypted  = cryptoService.decrypt(key, iv, ciphertext, tag)

      expect(decrypted).toBe('|`9oÄ¯]Ù©¤UµQCôÓèUÒ~vk')

    it 'should be able to decrypt what it encrypts', ->
      plaintext = 'may the force be with you'
      key       = '5wb/Vhk7dmM6jvCgC1Lltg=='
      iv        = 'ewcVcNXbhKK463r41DFS2g=='
      encrypted = cryptoService.encrypt(key, iv, plaintext)
      decrypted = cryptoService.decrypt(key, iv, encrypted.output.data, encrypted.mode.tag)

      expect(decrypted).toBe(plaintext)
