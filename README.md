# passport-okta-oauth

[Passport](http://passportjs.org/) strategies for authenticating with [Okta](https://www.okta.com/) using OAuth 2.0.

## Basic Setup

```
passport.use(new OktaStrategy({
  audience: process.env.OKTA_AUDIENCE,
  clientID: process.env.OKTA_CLIENTID,
  clientSecret: process.env.OKTA_CLIENTSECRET,
  idp: process.env.OKTA_IDP,
  scope: ['openid', 'email', 'profile'],
  response_type: 'code',
  callbackURL: baseURL + "/auth/okta/callback"
}, function(accessToken, refreshToken, profile, done) {
  var email, ref;
  email = ((ref = profile.emails[0]) != null ? ref.value.toLowerCase() : void 0) || '';
  return findByIdentifier(email, done);
}));
```

## Profile Object

```
  profile = {
    provider: 'okta-social',
    name: {
      fullName:   'John Smith',
      familyName: 'Smith',
      givenName:  'John'
    },
    emails: [{value: 'john.smith@example.com'}],
    _raw: "\{...\}"
    _json: {...}
  }
```