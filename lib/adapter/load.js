'use strict';

module.exports = function(name, opts) {
  try { return require('admit-one-' + name)(opts); }
  catch (e) {
    throw new Error('Could not find admit-one adapter ' + name + '.');
  }
};
