'use strict';

var _ = require('lodash');
var raise = require('./raise');

exports.defaults = _.partialRight(_.merge, function deep(value, other) {
  return _.merge(value, other, deep);
});

var param = exports.param = function(obj, field) {
  var chain = field.replace(/\]/g, '').split('[');
  return chain.reduce(function(obj, key) {
    return obj && obj[key];
  }, obj);
};

exports.extractParams = function(req, names/*, param, ...*/) {
  var params = Array.prototype.slice.call(arguments, 2);
  return function() {
    if (!req.body) { raise(400, 'missing body'); }
    params.forEach(function(name) {
      if (!(this[name] = param(req.body, names[name]))) {
        raise(400, 'missing parameter ' + names[name]);
      }
    }, this);
  };
};
