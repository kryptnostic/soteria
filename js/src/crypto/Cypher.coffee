define 'kryptnostic.cypher', [], (require) ->

  aesCtr128 = { algorithm : 'AES', mode: 'CTR', padding: 'NoPadding', keySize: 128 }
  aesGcm128 = { algorithm : 'AES', mode: 'GCM', padding: 'NoPadding', keySize: 128 }

  #
  # Enumeration of cyphers.
  # Author: rbuckheit
  #
  return {
    AES_CTR_128: aesCtr128
    AES_GCM_128: aesGcm128
    DEFAULT_CIPHER: aesGcm128
  }
