'use strict';

var sinon = require('sinon');
var expect = require('chai').expect;
var admit = require('..');

describe('admit', function() {
  it('fails for unknown modules', function() {
    expect(function() { admit('failname'); }).to
      .throw(/could not find admit-one adapter failname/i);
  });
});
