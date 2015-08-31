var allTestFiles  = [];
var allBuildFiles = [];
var allMockFiles  = [];

var TEST_REGEXP   = /(.*)(spec|test)\.(js|coffee)$/i;
var DIST_REGEXP   = /kryptnostic.js|KryptnosticClient.js/;
var SINON_REGEXP  = /sinon.js/;
var MOCK_REGEXP   = /mock(.*)\.(js)/;

var DEBUG         = false;

var pathToModule = function(path) {
  return path.replace(/^\/base\//, '').replace(/\.js$/, '');
};

var log = {
  info: function(message) {
    if (DEBUG) {
      window.console && console.info(message);
    }
  }
}

Object.keys(window.__karma__.files).forEach(function(file) {
  if (TEST_REGEXP.test(file)) {
    log.info('found TEST: ' + file);
    allTestFiles.push(pathToModule(file));
  }
  if (DIST_REGEXP.test(file)) {
    log.info('found DIST: ' + file);
    allBuildFiles.push(file);
  }
  if (SINON_REGEXP.test(file)) {
    log.info('found DEP: ' + file);
    allBuildFiles.push(file);
  }
  if (MOCK_REGEXP.test(file)) {
    log.info('found MOCK: ' + file);
    allMockFiles.push(pathToModule(file));
  }
});

var allFilesOrdered = allBuildFiles.concat(allMockFiles).concat(allTestFiles);

require.config({
  // Karma serves files under /base, which is the basePath from your config file
  baseUrl : '/base/lib',

  paths: {
    src   : '../src',
    test  : '../test'
  },

  // dynamically load all test files
  deps : allFilesOrdered,

  // we have to kickoff jasmine, as it is asynchronous
  callback: function() {
    // quiet noisy logger
    require('kryptnostic.logger').setLevel('warn');
    require('bluebird').longStackTraces();
    window.__karma__.start();
  }
});

