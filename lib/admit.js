'use strict';

var uuid = require('node-uuid');
var helpers = require('./helpers'),
    defaults = helpers.defaults;

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
  try { adapter = require('admit-one-' + adapter)(opts); }
  catch (e) {
    try { adapter = require(adapter)(opts); }
    catch (e) {
      throw new Error('Could not find admit-one adapter ' + adapter + '.');
    }
  }

  var exports = {};
  exports._adapter = adapter;

  exports.login =
    require('./middleware/login')(adapter, exports, opts);
  exports.create =
    require('./middleware/create')(adapter, exports, opts);
  exports.authenticate =
    require('./middleware/authenticate')(adapter, exports, opts);
  exports.authorize =
    require('./middleware/authorize')(adapter, exports, opts);
  exports.invalidate =
    require('./middleware/invalidate')(adapter, exports, opts);

  return exports;
};

module.exports.__uuid = uuid;
