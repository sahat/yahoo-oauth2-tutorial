var path = require('path');
var qs = require('querystring');
var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
var request = require('request');
var mongoose = require('mongoose');

var clientId = process.env.CLIENT_ID || 'dj0yJmk9dWd5RWlEMHBPUVpkJmQ9WVdrOWJHbExWMU4wTnpRbWNHbzlNQS0tJnM9Y29uc3VtZXJzZWNyZXQmeD0yNQ--';
var clientSecret = process.env.CLIENT_SECRET || 'c503aa14cdde1bb18f94e6318d861a196caa059b';
var redirectUri = process.env.REDIRECT_URI || 'http://myapp.com/auth/yahoo/callback';

var userSchema = new mongoose.Schema({
  guid: String,
  email: String,
  profileImage: String,
  firstName: String,
  lastName: String,
  accessToken: String
});

var User = mongoose.model('User', userSchema);

mongoose.connect(process.env.MONGODB || 'localhost');

var app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.set('port', process.env.PORT || 80);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function(req, res) {
  res.render('home', {
    title: 'Home',
    user: req.session.user
  });
});

app.get('/contacts', function(req, res) {
  if (!req.session.user) {
    return res.redirect('/auth/yahoo');
  }
  
  var user = req.session.user;
  var contactsApiUrl = 'https://social.yahooapis.com/v1/user/' + user.guid + '/contacts';

  var options = {
    url: contactsApiUrl,
    headers: { Authorization: 'Bearer ' + user.accessToken },
    rejectUnauthorized: false,
    json: true
  };

  request.get(options, function(err, response, body) {
    var contacts = body.contacts.contact.map(function(contact) {
      return contact.fields[0];
    });

    res.render('contacts', {
      title: 'Contacts',
      user: req.session.user,
      contacts: contacts
    });
  });
});

app.get('/logout', function(req, res) {
  delete req.session.user;
  res.redirect('/');
});

app.get('/auth/yahoo', function(req, res) {
  var authorizationUrl = 'https://api.login.yahoo.com/oauth2/request_auth';

  var queryParams = qs.stringify({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code'
  });

  res.redirect(authorizationUrl + '?' + queryParams);
});

app.get('/auth/yahoo/callback', function(req, res) {
  var accessTokenUrl = 'https://api.login.yahoo.com/oauth2/get_token';

  var options = {
    url: accessTokenUrl,
    headers: { Authorization: 'Basic ' + new Buffer(clientId + ':' + clientSecret).toString('base64') },
    rejectUnauthorized: false,
    json: true,
    form: {
      code: req.query.code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    }
  };

  // 1. Exchange authorization code for access token.
  request.post(options, function(err, response, body) {
    var guid = body.xoauth_yahoo_guid;
    var accessToken = body.access_token;
    var socialApiUrl = 'https://social.yahooapis.com/v1/user/' + guid + '/profile?format=json';

    var options = {
      url: socialApiUrl,
      headers: { Authorization: 'Bearer ' + accessToken },
      rejectUnauthorized: false,
      json: true
    };

    // 2. Retrieve profile information about the current user.
    request.get(options, function(err, response, body) {

      // 3. Create a new user account or return an existing one.
      User.findOne({ guid: guid }, function(err, existingUser) {
        if (existingUser) {
          req.session.user = existingUser;
          return res.redirect('/');
        }

        var user = new User({
          guid: guid,
          email: body.profile.emails[0].handle,
          profileImage: body.profile.image.imageUrl,
          firstName: body.profile.givenName,
          lastName: body.profile.familyName,
          accessToken: accessToken

        });

        user.save(function(err) {
          req.session.user = user;
          res.redirect('/');
        });
      });
    });
  });
});

app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});
