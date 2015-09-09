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
      ciphertext = atob('5wb/Vhk7dmM6jvCgC1Lltg==')
      key        = atob('6veqEBl0TNxneQfnfpLbeRey5Yfe4oIKOqrepHn5vac=')
      iv         = atob('ewcVcNXbhKK463r41DFS2g==')
      decrypted  = cryptoService.decrypt(ciphertext, iv, key)

      expect(decrypted).toBe('¢búð)lÚèKwz\'öOXfþP¦ã¾þlTíMY')

    it 'should be able to decrypt what it encrypts', ->
      plaintext = 'may the force be with you'
      key       = '5wb/Vhk7dmM6jvCgC1Lltg=='
      iv        = 'ewcVcNXbhKK463r41DFS2g=='
      encrypted = cryptoService.encrypt(key, iv, plaintext)
      decrypted = cryptoService.decrypt(key, iv, encrypted)

      expect(decrypted).toBe(plaintext)
