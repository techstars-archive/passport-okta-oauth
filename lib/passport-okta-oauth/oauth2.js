/**
 * Module dependencies.
 */
var util = require('util')
  , uid = require('uid2')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


function Strategy(option, verify) {
  option = option || {};
  option.authorizationURL = option.audience + "/oauth2/v1/authorize";
  option.tokenURL = option.audience + "/oauth2/v1/token";
  option.userInfoUrl = option.audience + "/oauth2/v1/userinfo";
  option.state = true;
  option.nonce = uid(24);

  OAuth2Strategy.call(this, option, verify);

  this.name = 'okta';
  this.authorizationURL = option.authorizationURL
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Okta.
 * Further References at http://developer.okta.com/docs/api/resources/oidc.html#get-user-information
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `okta`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

Strategy.prototype.userProfile = function(accessToken, done) {
  var post_headers = { 'Authorization': 'Bearer ' + accessToken };

  this._oauth2._request('POST', profileURL, post_headers, "", null, function(err, body, res){
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);

      var profile = { provider: 'okta' };
      profile.id = json.sub;
      profile.displayName = json.name;
      profile.username = json.preferred_username;
      profile.name = {
        fullName: json.name,
        familyName: json.family_name,
        givenName: json.given_name
      };
      profile.emails = [{ value: json.email }];

      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }

  });
}

/**
 * Return extra Okta-specific parameters to be included in the authorization
 * request.
 *
 * @param {Object} option
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(option) {
  var params = {};
  if (option.idp) {
    params["idp"] = option.idp;
  }
  if (option.clientID) {
    params["client_id"] = option.clientID;
  }
  if (option.nonce) {
    params["nonce"] = option.nonce;
  }
  if (option.redirectURL) {
    params["redirect_uri"] = option.redirectURL;
  }
  return params;
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
