'use strict';

var _ = require('lodash');

module.exports.defaults = _.partialRight(_.merge, function deep(value, other) {
  return _.merge(value, other, deep);
});

module.exports.param = function(obj, field) {
  var chain = field.replace(/\]/g, '').split('[');
  return chain.reduce(function(obj, key) {
    return obj && obj[key];
  }, obj);
};
