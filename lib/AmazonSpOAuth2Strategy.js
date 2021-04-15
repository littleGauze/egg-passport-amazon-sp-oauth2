/* eslint-disable no-inner-declarations */
'use strict';

const url = require('url');
const { AuthorizationError, Strategy: OAuth2Strategy } = require('passport-oauth2');
const utils = require('./utils');
const base64url = require('base64url');
const crypto = require('crypto');

class AmazonSpOAuth2Strategy extends OAuth2Strategy {
  constructor(options, verify) {
    if (!options.applicationId) { throw new TypeError('AmazonSpOAuth2Strategy requires a applicationId'); }
    super(options, verify);
  }

  _getAuthorizeUrl(options) {
    if (options.authorizationURL) return options.authorizationURL;
    return this._oauth2._authorizeUrl;
  }

  authorizationParams(options) {
    const params = {};
    if (options.beta) {
      params.version = 'beta';
    }

    params.application_id = options.applicationId;

    return params;
  }

  authenticate(req, options) {
    options = options || {};
    const self = this;

    if (req.query && req.query.error) {
      if (req.query.error === 'access_denied') {
        return this.fail({ message: req.query.error_description });
      }
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));

    }

    let callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      const parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
      }
    }

    const meta = {
      authorizationURL: this._oauth2._authorizeUrl,
      tokenURL: this._oauth2._accessTokenUrl,
      clientID: this._oauth2._clientId,
    };

    if (req.query && req.query.spapi_oauth_code) {
      function loaded(err, ok, state) {
        if (err) { return self.error(err); }
        if (!ok) {
          return self.fail(state, 403);
        }

        const code = req.query.spapi_oauth_code;

        // save sellinng partner id
        self._verify(req);

        const params = self.tokenParams(options);
        params.grant_type = 'authorization_code';
        if (callbackURL) { params.redirect_uri = callbackURL; }
        if (typeof ok === 'string') { // PKCE
          params.code_verifier = ok;
        }

        self._oauth2.getOAuthAccessToken(code, params,
          function(err, accessToken, refreshToken, params) {
            if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

            self._loadUserProfile(accessToken, function(err, profile) {
              if (err) { return self.error(err); }

              function verified(err, user, info) {
                if (err) { return self.error(err); }
                if (!user) { return self.fail(info); }

                info = info || {};
                if (state) { info.state = state; }
                self.success(user, info);
              }

              try {
                if (self._passReqToCallback) {
                  const arity = self._verify.length;
                  if (arity === 6) {
                    self._verify(req, accessToken, refreshToken, params, profile, verified);
                  } else { // arity == 5
                    self._verify(req, accessToken, refreshToken, profile, verified);
                  }
                } else {
                  const arity = self._verify.length;
                  if (arity === 5) {
                    self._verify(accessToken, refreshToken, params, profile, verified);
                  } else { // arity == 4
                    self._verify(accessToken, refreshToken, profile, verified);
                  }
                }
              } catch (ex) {
                return self.error(ex);
              }
            });
          }
        );
      }

      const state = req.query.state;
      try {
        const arity = this._stateStore.verify.length;
        if (arity === 4) {
          this._stateStore.verify(req, state, meta, loaded);
        } else { // arity == 3
          this._stateStore.verify(req, state, loaded);
        }
      } catch (ex) {
        return this.error(ex);
      }
    } else {
      const params = this.authorizationParams(options);
      let verifier,
        challenge;

      if (this._pkceMethod) {
        verifier = base64url(crypto.pseudoRandomBytes(32));
        switch (this._pkceMethod) {
          case 'plain':
            challenge = verifier;
            break;
          case 'S256':
            challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
            break;
          default:
            return this.error(new Error('Unsupported code verifier transformation method: ' + this._pkceMethod));
        }

        params.code_challenge = challenge;
        params.code_challenge_method = this._pkceMethod;
      }

      const state = options.state;
      if (state) {
        params.state = state;

        const parsed = url.parse(this._getAuthorizeUrl(options), true);
        utils.merge(parsed.query, params);
        delete parsed.search;
        const location = url.format(parsed);
        this.redirect(location);
      } else {
        function stored(err, state) {
          if (err) { return self.error(err); }

          if (state) { params.state = state; }
          const parsed = url.parse(self._getAuthorizeUrl(options), true);
          utils.merge(parsed.query, params);
          delete parsed.search;
          const location = url.format(parsed);
          self.redirect(location);
        }

        try {
          const arity = this._stateStore.store.length;
          if (arity === 5) {
            this._stateStore.store(req, verifier, undefined, meta, stored);
          } else if (arity === 3) {
            this._stateStore.store(req, meta, stored);
          } else { // arity == 2
            this._stateStore.store(req, stored);
          }
        } catch (ex) {
          return this.error(ex);
        }
      }
    }
  }
}

module.exports = AmazonSpOAuth2Strategy;
