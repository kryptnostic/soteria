define 'kryptnostic.password-crypto-service', [
  'require',
  'forge',
  'kryptnostic.abstract-crypto-service'
], (require) ->
  'use strict'

  Forge                 = require 'forge'
  AbstractCryptoService = require 'kryptnostic.abstract-crypto-service'
  BlockCiphertext       = require 'kryptnostic.block-ciphertext'

  derive = (password, salt, iterations, keySize) ->
    md = Forge.sha1.create()
    return Forge.pkcs5.pbkdf2(password, salt, iterations, keySize, md)

  #
  # Crypto service which encrypts and decrypts using the user's password.
  # Author: nickdhewitt, rbuckheit
  #
  class PasswordCryptoService

    constructor: (@cypher) ->
      @abstractCryptoService = new AbstractCryptoService(@cypher)

    encrypt: (plaintext, password) ->
      blockCipherKeySize    = AbstractCryptoService.BLOCK_CIPHER_KEY_SIZE
      blockCipherIterations = AbstractCryptoService.BLOCK_CIPHER_ITERATIONS

      salt       = Forge.random.getBytesSync(blockCipherKeySize)
      key        = derive(password, salt, blockCipherIterations, blockCipherKeySize)
      iv         = Forge.random.getBytesSync(blockCipherKeySize)

      encryption = @abstractCryptoService.encrypt(key, iv, plaintext)

      ciphertext = encryption.output.data
      tag        = encryption.mode.tag.getBytes()
      return new BlockCiphertext {
        contents : btoa(ciphertext)
        tag      : btoa(tag)
        iv       : btoa(iv)
        salt     : btoa(salt)
      }

    decrypt: (blockCiphertext, password) ->
      blockCipherKeySize    = AbstractCryptoService.BLOCK_CIPHER_KEY_SIZE
      blockCipherIterations = AbstractCryptoService.BLOCK_CIPHER_ITERATIONS

      salt     = atob(blockCiphertext.salt)
      key      = derive(password, salt, blockCipherIterations, blockCipherKeySize)
      iv       = atob(blockCiphertext.iv)
      contents = atob(blockCiphertext.contents)
      tag      = atob(blockCiphertext.tag)
      return @abstractCryptoService.decrypt(key, iv, contents, tag)

    _derive: (password, salt, iterations, keySize) ->
      return derive(password, salt, iterations, keySize)

  return PasswordCryptoService
