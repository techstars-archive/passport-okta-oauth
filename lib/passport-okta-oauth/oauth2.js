/**
 * Module dependencies.
 */
var util = require('util')
  , uid = require('uid2')
  , querystring= require('querystring')
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
  this._userInfoUrl = option.userInfoUrl;
  this._idp = option.idp;

  // Authorize Request using Authorization Header
  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    var codeParam, post_data, post_headers;
    params = params || {};
    codeParam = params.grant_type === 'refresh_token' ? 'refresh_token' : 'code';
    params[codeParam] = code;
    post_data = querystring.stringify(params);
    post_headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic: ' + new Buffer(this._clientId + ":" + this._clientSecret).toString('base64')
    };
    this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
      if( error )  callback(error);
      else {
        var results;
        try {
          // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
          // responses should be in JSON
          results= JSON.parse( data );
        }
        catch(e) {
          // .... However both Facebook + Github currently use rev05 of the spec
          // and neither seem to specify a content-type correctly in their response headers :(
          // clients of these services will suffer a *minor* performance cost of the exception
          // being thrown
          results= querystring.parse( data );
        }
        var access_token= results["access_token"];
        var refresh_token= results["refresh_token"];
        delete results["refresh_token"];
        callback(null, access_token, refresh_token, results); // callback results =-=
      }
    });

  };
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

  this._oauth2._request('POST', this._userInfoUrl, post_headers, "", null, function(err, body, res){
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
  if(this._idp) {
    params["idp"] = this._idp;
  }
  return params;
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
