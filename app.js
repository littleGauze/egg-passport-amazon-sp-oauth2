'use strict';

const assert = require('assert');
const AmazonSpOAuth2Strategy = require('./lib/AmazonSpOAuth2Strategy');

module.exports = app => {
  const config = app.config.passportAmazonSpOauth2;
  config.passReqToCallback = true;
  assert(config.key, '[egg-passport-amazon-sp-oauth2] config.passportAmazonSpOauth2.key required');
  assert(config.secret, '[egg-passport-amazon-sp-oauth2] config.passportAmazonSpOauth2.secret required');
  assert(config.applicationId, '[egg-passport-amazon-sp-oauth2] config.passportAmazonSpOauth2.applicationId required');

  const options = {
    clientID: config.key,
    clientSecret: config.secret,
    authorizationURL: config.authorizationURL,
    tokenURL: config.accessTokenURL,
    applicationId: config.applicationId,
    beta: config.beta,
    passReqToCallback: true,
  };

  app.passport.use('amazon-sp-oauth2', new AmazonSpOAuth2Strategy(options, function verify(req, token, refreshToken, params, profile, done) {
    // save auth info
    if (!done) {
      app.passport.doVerify(req, null, () => {});
      return;
    }

    const user = {
      provider: 'amazon-sp',
      id: req.query.state,
      token,
      refreshToken,
      params,
      profile,
    };

    app.passport.doVerify(req, user, done);
  }));
};
