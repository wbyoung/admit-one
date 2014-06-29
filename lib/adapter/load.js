'use strict';

module.exports = function(name, opts) {
  var adapter;
  try { adapter = require('admit-one-' + name)(opts); }
  catch (e) {
    try { adapter = require(name)(opts); }
    catch (e) {
      throw new Error('Could not find admit-one adapter ' + name + '.');
    }
  }
  return adapter;
};
