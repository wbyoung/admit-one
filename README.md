# Admit One

[![NPM version][npm-image]][npm-url] [![Build status][travis-image]][travis-url] [![Code Climate][codeclimate-image]][codeclimate-url] [![Coverage Status][coverage-image]][coverage-url] [![Dependencies][david-image]][david-url] [![devDependencies][david-dev-image]][david-dev-url]

Admit One is an extensible authentication and authorization system for Node.js
applications that require token based authentication. It aims to be incredibly
easy to configure with varying databases, ORM tools, and front end frameworks.


## Available Extensions

### Backend

- [`admit-one-mongo`][admit-one-mongo]
- [`admit-one-bookshelf`][admit-one-bookshelf]

### Frontend

- [`admit-one-ember`][admit-one-ember]


## Usage

The following example uses [`admit-one-mongo`][admit-one-mongo].

```javascript
var admit = require('admit-one-mongo')({
  mongo: {
    db: 'mongodb://localhost/dbname'
  }
});

var app = express();
var api = express.Router();

app.use(require('body-parser').json());

api.post('/users', admit.create, function(req, res) {
  // user accessible via req.auth.user
  res.json({ status: 'ok' });
});

api.post('/sessions', admit.authenticate, function(req, res) {
  // user accessible via req.auth.user
  res.json({ status: 'ok' });
});

// all routes defined from here on will require authorization
api.use(admit.authorize);
api.delete('/sessions/current', admit.invalidate, function(req, res) {
  if (req.auth.user) { throw new Error('Session not invalidated.'); }
  res.json({ status: 'ok' });
});

// application routes
app.use('/api', api);
```

## Comparison to Passport

This project differs from [Passport][passport] in that it defines a single
strategy for user creation, authentication, and authorization. That strategy
is what Passport refers to as a _basic_ strategy. Unfortunately, though,
Passport leaves it up to developers to properly handle the secure storage of
passwords during user creation and properly verifying passwords during
authentication.


## API

### admit([options])

#### options.username

Type: `String`  
Default: `'username'`

#### options.password

Type: `String`  
Default: `'password'`

#### options.passwordDigest

Type: `String`  
Default: `'passwordDigest'`

#### options.params.create.username

Type: `String`  
Default: `'user[username]'`

#### options.params.create.password

Type: `String`  
Default: `'user[password]'`

#### options.params.authenticate.username

Type: `String`  
Default: `'session[username]'`

#### options.params.authenticate.password

Type: `String`  
Default: `'session[password]'`

#### options.bcryptRounds

Type: `Number`  
Default: `12`


## Security

There are a few places that this project can be improved in terms of security:

- Longer tokens could be issued or the token could be signed to prevent an
  attacker from more easily performing a brute force attack against the token
  generation algorithm
- Tokens could be expired after a set amount of time for increased security

These points are not flaws that should affect the security of your users' data
and will not prevent your application from running securely.


## License

This project is distributed under the MIT license.


[travis-url]: http://travis-ci.org/wbyoung/admit-one
[travis-image]: https://secure.travis-ci.org/wbyoung/admit-one.png?branch=master
[npm-url]: https://npmjs.org/package/admit-one
[npm-image]: https://badge.fury.io/js/admit-one.png
[codeclimate-image]: https://codeclimate.com/github/wbyoung/admit-one.png
[codeclimate-url]: https://codeclimate.com/github/wbyoung/admit-one
[coverage-image]: https://coveralls.io/repos/wbyoung/admit-one/badge.png
[coverage-url]: https://coveralls.io/r/wbyoung/admit-one
[david-image]: https://david-dm.org/wbyoung/admit-one.png?theme=shields.io
[david-url]: https://david-dm.org/wbyoung/admit-one
[david-dev-image]: https://david-dm.org/wbyoung/admit-one/dev-status.png?theme=shields.io
[david-dev-url]: https://david-dm.org/wbyoung/admit-one#info=devDependencies

[admit-one-mongo]: https://github.com/wbyoung/admit-one-mongo
[admit-one-bookshelf]: https://github.com/wbyoung/admit-one-bookshelf
[admit-one-ember]: https://github.com/wbyoung/admit-one-ember

[passport]: http://passportjs.org
