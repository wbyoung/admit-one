'use strict';

module.exports = function(adapter, middleware, opts) {
  var load = function(name) {
    return require('./middleware/' + name)(adapter, middleware, opts);
  };
  return {
    _login: load('login'),
    create: load('create'),
    authenticate: load('authenticate'),
    authorize: load('authorize'),
    invalidate: load('invalidate')
  };
};
