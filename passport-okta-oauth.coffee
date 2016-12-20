uid = require('uid2')
OAuth2Strategy = require('passport-oauth').OAuth2Strategy
InternalOAuthError = require('passport-oauth').InternalOAuthError

class Strategy extends OAuth2Strategy
  constructor: (@options, @verify)->
    # Add Validation?
    @options.authorizationURL = "#{@options.audience}/oauth2/v1/authorize"
    @options.tokenURL = "#{@options.audience}/oauth2/v1/token"
    @options.userInfoUrl = "#{@options.audience}/oauth2/v1/userinfo"
    @options.state = true
    @options.nonce = uid(24)

    OAuth2Strategy.call(@, @options, @verify)
    @name = "okta-social"

  userProfile: (accessToken, callback) ->
    post_headers = { 'Authorization': 'Bearer ' + accessToken }
    @._oauth2._request 'POST', @options.userInfoUrl, post_headers, "", null, (err, body, res) ->

      if(err)
        return callback(new InternalOAuthError('failed to fetch user profile', err));

      try
        json = JSON.parse(body);

        profile = {provider: 'okta-social'}

        profile.name = {
          fullName: json.name,
          familyName: json.family_name,
          givenName: json.given_name
        }
        profile.emails = [{ value: json.email }]
        profile._raw = body
        profile._json = json


        callback(null, profile)
      catch e
        callback(e)

  authorizationParams: (options) ->
    params = {};

    if @options.idp
      params["idp"] = @options.idp

    if @options.clientID
      params["client_id"] = @options.clientID

    if @options.nonce
      params["nonce"] = @options.nonce

    if @options.redirectURL
      params["redirect_uri"] = @options.redirectURL

    return params;


module.exports = { Strategy: Strategy }
