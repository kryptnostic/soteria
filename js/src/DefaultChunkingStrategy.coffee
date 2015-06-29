define 'soteria.chunking.strategy.default', [
  'require',
  'lodash',
], (require) ->

  _ = require 'lodash'

  BLOCK_LENGTH_IN_BYTES = 4096

  #
  # Chunking strategy which separates stored data into a fixed-size chunks.
  # Author: rbuckheit
  #
  class DefaultChunkingStrategy

    @URI : 'soteria.chunking.strategy.default'

    split : (data) ->
      return _.chain(data)
        .chunk(BLOCK_LENGTH_IN_BYTES)
        .map((chunkArr) -> chunkArr.join())
        .value()

    join : (chunks) ->
      return chunks.join()

  return DefaultChunkingStrategy
