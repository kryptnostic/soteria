define 'kryptnostic.authentication-service', [
  'require'
  'bluebird'
  'kryptnostic.logger'
  'kryptnostic.configuration'
  'kryptnostic.credential-provider-loader'
  'kryptnostic.credential-service'
  'kryptnostic.search-credential-service'
  'kryptnostic.authentication-stage'
  'kryptnostic.user-directory-api'
  'kryptnostic.kryptnostic-engine-provider'
], (require) ->

  Promise                   = require 'bluebird'
  Logger                    = require 'kryptnostic.logger'
  Config                    = require 'kryptnostic.configuration'
  CredentialProviderLoader  = require 'kryptnostic.credential-provider-loader'
  CredentialService         = require 'kryptnostic.credential-service'
  SearchCredentialService   = require 'kryptnostic.search-credential-service'
  AuthenticationStage       = require 'kryptnostic.authentication-stage'
  UserDirectoryApi          = require 'kryptnostic.user-directory-api'
  KryptnosticEngineProvider = require 'kryptnostic.kryptnostic-engine-provider'

  logger = Logger.get('AuthenticationService')

  LOGIN_FAILURE_MESSAGE = 'invalid credentials'

  #
  # Allows user to authenticate and derives their credential.
  # Author: rbuckheit
  #
  class AuthenticationService

    # authenticates, and forces initialization of keys if needed.
    @authenticate: ( { email, password }, notifier = -> ) ->
      { principal, credential, keypair } = {}

      credentialService       = new CredentialService()
      userDirectoryApi        = new UserDirectoryApi()

      credentialProvider = CredentialProviderLoader.load(Config.get('credentialProvider'))

      Promise.resolve()
      .then ->
        userDirectoryApi.resolve({ email })
      .then (uuid) ->
        if _.isEmpty(uuid)
          throw new Error LOGIN_FAILURE_MESSAGE
        principal = uuid
        logger.info('authenticating', email)
        credentialService.deriveCredential({ principal, password }, notifier)
      .then (_credential) ->
        credential = _credential
        logger.info('derived credential')
        credentialProvider.store { principal, credential }
        credentialService.deriveKeypair({ password }, notifier)
      .then (_keypair) ->
        keypair = _keypair
        credentialProvider.store { principal, credential, keypair }
      .then ->
        AuthenticationService.initializeEngine()
      .then ->
        Promise.resolve(notifier(AuthenticationStage.COMPLETED))
      .then ->
        logger.info('authentication complete')

    @initializeEngine: ->

      searchCredentialService = new SearchCredentialService()

      Promise.resolve()
      .then ->
        searchCredentialService.getAllCredentials()
      .then (_searchCredential) ->
        searchCredential = _searchCredential
        fhePrivateKey = searchCredential.FHE_PRIVATE_KEY
        searchPrivateKey = searchCredential.SEARCH_PRIVATE_KEY
        KryptnosticEngineProvider.init({ fhePrivateKey, searchPrivateKey })
        logger.info('KryptnosticEngine initialized')

    @destroy: ->
      credentialProvider = CredentialProviderLoader.load(Config.get('credentialProvider'))
      return credentialProvider.destroy()

  return AuthenticationService
