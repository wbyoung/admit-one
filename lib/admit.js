'use strict';

var _ = require('lodash');
var uuid = require('node-uuid');
var defaults = require('./helpers').defaults;
var loadAdapter = require('./adapter/load');

module.exports = function(adapter, options) {
  var opts = defaults({}, options, {
    username: 'username',
    password: 'password',
    params: { create: {}, authenticate: {} },
    bcryptRounds: 12
  });

  opts.passwordDigest = opts.passwordDigest ||
    opts.password + 'Digest';
  opts.params.create.username = opts.params.create.username ||
    'user[' + opts.username + ']';
  opts.params.create.password = opts.params.create.password ||
    'user[' + opts.password + ']';
  opts.params.authenticate.username = opts.params.authenticate.username ||
    'session[' + opts.username + ']';
  opts.params.authenticate.password = opts.params.authenticate.password ||
    'session[' + opts.password + ']';


  // create the adapter and give it access to all of the options that have been
  // passed to admit-one.
  adapter = loadAdapter(adapter, opts);

  var exports = {};
  _.extend(exports, { _adapter: adapter },
    require('./middleware')(adapter, exports, opts));

  return exports;
};

module.exports.__uuid = uuid;
