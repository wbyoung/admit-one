'use strict';

var env = process.env.NODE_ENV || 'development';
var development = env === 'development';

var _type = (function() {
  var StringClass = String; // unique string w/o JSHint warning
  return new StringClass('http');
}());

var raise = module.exports = exports = function(code, message, debug) {
  if (debug && development) { message = [message, debug].join(' '); }
  var error = new Error(message);
  error.code = code || 500;
  error.type = String(_type);
  error._type = _type;
  throw error;
};

exports.verify = {};
exports.verify.not = {};

exports.verify.defined = function(code, message, debug) {
  return function(value) {
    if (!value) { raise(code, message, debug); }
  };
};

exports.verify.not.defined = function(code, message, debug) {
  return function(value) {
    if (value) { raise(code, message, debug); }
  };
};

exports.catch = function(cb) {
  return function(e) {
    if (e._type !== _type) { throw e; }
    cb(e);
  };
};
