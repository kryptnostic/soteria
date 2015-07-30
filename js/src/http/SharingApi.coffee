define 'kryptnostic.sharing-api', [
  'require'
  'axios'
  'bluebird'
  'kryptnostic.configuration'
  'kryptnostic.security-utils'
  'kryptnostic.logger'
], (require) ->

  axios         = require 'axios'
  SecurityUtils = require 'kryptnostic.security-utils'
  Logger        = require 'kryptnostic.logger'
  Config        = require 'kryptnostic.configuration'
  Promise       = require 'bluebird'

  sharingUrl        = -> Config.get('servicesUrl') + '/share'

  TYPE_PATH         = '/type'
  SHARE_PATH        = '/share'
  REVOKE_PATH       = '/revoke'
  OBJECT_PATH       = '/object'
  KEYS_PATH         = '/keys'

  logger            = Logger.get('SharingApi')

  DEFAULT_HEADER = { 'Content-Type' : 'application/json' }

  #
  # HTTP calls for interacting with the /share endpoint of Kryptnostic Services.
  # Author: rbuckheit
  #
  class SharingApi

    # get all incoming shares
    getIncomingShares : ->
      axios(SecurityUtils.wrapRequest({
        url    : sharingUrl() + OBJECT_PATH
        method : 'GET'
      }))
      .then (response) ->
        return response.data

    # share an object
    shareObject: (sharingRequest) ->
      Promise.resolve()
      .then ->
        sharingRequest.validate()

        axios(SecurityUtils.wrapRequest({
          url     : sharingUrl() + OBJECT_PATH + SHARE_PATH
          method  : 'POST'
          headers : _.clone(DEFAULT_HEADER)
          data    : JSON.stringify(sharingRequest)
        }))
      .then (response) ->
        logger.debug('shareObject', response.data.data)

    # revoke access to an object
    revokeObject: (revocationRequest) ->
      revocationRequest.validate()

      axios(SecurityUtils.wrapRequest({
        url     : sharingUrl() + OBJECT_PATH + REVOKE_PATH
        method  : 'POST'
        headers : _.clone(DEFAULT_HEADER)
        data    : JSON.stringify(revocationRequest)
      }))
      .then (response) ->
        logger.debug('revokeObject', response.data.data)

    # register keys
    registerKeys: (keyRegistrationRequest) ->
      keyRegistrationRequest.validate()

      axios(SecurityUtils.wrapRequest({
        url     : sharingUrl() + KEYS_PATH
        method  : 'POST'
        headers : _.clone(DEFAULT_HEADER)
        data    : JSON.stringify(keyRegistrationRequest)
      }))
      .then (response) ->
        logger.debug('registerKeys', response)
        return response.data

    # register search keys
    registerSearchKeys: (encryptedSearchObjectKeys) ->
      throw new Error 'unimplemented'

  return SharingApi
