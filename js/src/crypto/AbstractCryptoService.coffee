define 'kryptnostic.abstract-crypto-service', [
  'require'
  'forge'
], (require) ->

  Forge           = require 'forge'

  #
  # Author: nickdhewitt, rbuckheit
  #
  class AbstractCryptoService

    @BLOCK_CIPHER_ITERATIONS : 128
    @BLOCK_CIPHER_KEY_SIZE   : 16
    @BITS_PER_BYTE           : 8

    constructor: ({ @algorithm, @mode, @tagLength }) ->
      unless @algorithm is 'AES' and @mode in ['CTR', 'GCM']
        throw new Error 'cypher not supported'

    encrypt: (key, iv, plaintext) ->
      cipher = Forge.cipher.createCipher(@algorithm + '-' + @mode, key)
      cipher.start({
        iv: iv
      })
      cipher.update(Forge.util.createBuffer(plaintext))
      cipher.finish()
      return cipher

    decrypt: (key, iv, ciphertext, tag) ->
      decipher = Forge.cipher.createDecipher(@algorithm + '-' + @mode, key)
      decipher.start({
        iv: iv,
        tag: tag
      })
      decipher.update(Forge.util.createBuffer(ciphertext))
      decipher.finish()
      return decipher.output.data

  return AbstractCryptoService
