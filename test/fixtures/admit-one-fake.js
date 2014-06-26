'use strict';

var _ = require('lodash');
var admit = require('../..');

module.exports = function(options) {
  var opts = admit.helpers.defaults(options || {});

  var create = function(username, passwordDigest) {
  };

  var find = function(username) {
  };

  var findByToken = function(token) {
  };

  var addToken = function(user, digest) {
    return true;
  };

  var removeToken = function(user, digest) {
    return true;
  };

  opts._users = {
    create: create,
    find: find,
    findByToken: findByToken,
    addToken: addToken,
    removeToken: removeToken
  };

  opts._attrs = {
    passwordDigest: function(user) { return user[opts.passwordDigest]; }
  };

  return _.extend(admit(opts), { _options: opts });
};

module.exports.__admit = admit;
