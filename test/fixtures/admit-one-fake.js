'use strict';

module.exports = function(/*options*/) {
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

  var adapter = {};

  adapter.users = {
    create: create,
    find: find,
    findByToken: findByToken,
    addToken: addToken,
    removeToken: removeToken
  };

  adapter.attrs = {
    all: function(user) { return user; }
  };

  return adapter;
};
