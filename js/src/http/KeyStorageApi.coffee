define 'kryptnostic.key-storage-api', [
  'require'
  'axios'
  'bluebird'
  'kryptnostic.configuration'
  'kryptnostic.kryptnostic-object'
  'kryptnostic.logger'
  'kryptnostic.requests'
  'kryptnostic.object-metadata'
  'kryptnostic.validators'
], (require) ->

  # libraries
  axios   = require 'axios'
  Promise = require 'bluebird'

  # utils
  Config   = require 'kryptnostic.configuration'
  Logger   = require 'kryptnostic.logger'
  Requests = require 'kryptnostic.requests'

  logger = Logger.get('KeyStorageApi')

  DEFAULT_HEADER = { 'Content-Type' : 'application/json' }

  keyStorageApi = -> Config.get('servicesUrlV2') + '/keys'
  saltUrl       = (userId) -> keyStorageApi() + '/salt/' + userId

  #
  # FHE endpoints
  #

  fheKeysUrl             = -> keyStorageApi() + '/fhe'
  fheHashUrl             = -> fheKeysUrl() + '/hash'
  fhePrivateKeyUrl       = -> fheKeysUrl() + '/private'
  fheSearchPrivateKeyUrl = -> fheKeysUrl() + '/searchprivate'

  #
  # RSA endpoints
  #

  rsaKeysUrl       = -> keyStorageApi() + '/rsa'
  rsaPublicKeyUrl  = -> rsaKeysUrl() + '/public'
  rsaPrivateKeyUrl = -> rsaKeysUrl() + '/private'

  class KeyStorageApi

    #
    # FHE private key
    #

    getFHEPrivateKey: ->
      Requests.getBlockCiphertextFromUrl(
        fhePrivateKeyUrl()
      )

    setFHEPrivateKey: (fhePrivateKey) ->
      Promise.resolve(
        axios(
          Requests.wrapCredentials({
            method  : 'POST'
            url     : fhePrivateKeyUrl()
            data    : fhePrivateKey
            headers : _.clone(DEFAULT_HEADER)
          })
        )
      )

    #
    # FHE search private key
    #

    getFHESearchPrivateKey: ->
      Requests.getBlockCiphertextFromUrl(
        fheSearchPrivateKeyUrl()
      )

    setFHESearchPrivateKey: (fheSearchPrivateKey) ->
      Promise.resolve(
        axios(
          Requests.wrapCredentials({
            method  : 'POST'
            url     : fheSearchPrivateKeyUrl()
            data    : fheSearchPrivateKey
            headers : _.clone(DEFAULT_HEADER)
          })
        )
      )

    #
    # FHE client hash function
    #

    getFHEHashFunction: ->
      Requests.getAsUint8FromUrl(
        fheHashUrl()
      )

    setFHEHashFunction: (fheHashFunction) ->
      Promise.resolve(
        axios(
          Requests.wrapCredentials({
            method  : 'POST'
            url     : fheHashUrl()
            data    : fheHashFunction
            headers : _.clone(DEFAULT_HEADER)
          })
        )
      )

  #
  # encrypted salt
  #

  getEncryptedSalt: (userId) ->
    throw new Error('not yet implemented')

  setEncryptedSalt: (userId, blockCiphertext) ->
    throw new Error('not yet implemented')


  return KeyStorageApi
