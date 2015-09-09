define 'kryptnostic.aes-crypto-service', [
  'require',
  'forge',
  'kryptnostic.abstract-crypto-service'
  'kryptnostic.logger'
  'kryptnostic.block-ciphertext'
], (require) ->
  'use strict'

  Forge                 = require 'forge'
  AbstractCryptoService = require 'kryptnostic.abstract-crypto-service'
  Logger                = require 'kryptnostic.logger'
  BlockCiphertext       = require 'kryptnostic.block-ciphertext'

  logger = Logger.get('AesCryptoService')

  #
  # Author: nickdhewitt, rbuckheit
  #
  class AesCryptoService


    constructor: (@cypher, @key) ->
      if not @key
        logger.info('no key passed! generating a key.')
        @key = Forge.random.getBytesSync(cypher.keySize / AbstractCryptoService.BITS_PER_BYTE)
      @abstractCryptoService = new AbstractCryptoService(cypher)

    encrypt: (plaintext) ->
      iv         = Forge.random.getBytesSync(AbstractCryptoService.BLOCK_CIPHER_KEY_SIZE)
      ciphertext = @abstractCryptoService.encrypt(@key, iv, plaintext)

      return new BlockCiphertext {
        iv       : btoa(iv)
        salt     : btoa(Forge.random.getBytesSync(0))
        contents : btoa(ciphertext)
      }

    decrypt: (blockCiphertext) ->
      iv       = atob(blockCiphertext.iv)
      contents = atob(blockCiphertext.contents)
      return @abstractCryptoService.decrypt(@key, iv, contents)

  return AesCryptoService
