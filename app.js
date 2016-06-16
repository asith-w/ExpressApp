var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var routes = require('./routes/index');
var users = require('./routes/users');

//var logger = require('connect-logger');
//var cookieParser = require('cookie-parser');
var session = require('cookie-session');
var fs = require('fs');
var crypto = require('crypto');
var request = require('request');
var jwt = require('jsonwebtoken');



var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(require('stylus').middleware(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);
app.use('/users', users);



app.get('/auth', function (req, res) {
    crypto.randomBytes(48, function (ex, buf) {
        var token = buf.toString('base64').replace(/\//g, '_').replace(/\+/g, '-');
        res.cookie('authstate', token);
        
        var adminAuthorizationUrl = authorizeEndpoint + 
                                '?response_type = code' +
                                '&client_id=' + clientId +
                                '&resource=' + resource +
                                '&redirect_uri=' + redirectUri +
                                '&state=' + state + 
                                '&prompt=admin_consent';
        
        res.redirect(adminAuthorizationUrl);
    });
    
});

app.get('/authuser', function (req, res) {
    crypto.randomBytes(48, function (ex, buf) {
        var token = buf.toString('base64').replace(/\//g, '_').replace(/\+/g, '-');
        res.cookie('authstate', token);
        
        var userAuthorizationUrl = authorizeEndpoint + 
                                '?response_type = code' +
                                '&client_id=' + clientId +
                                '&resource=' + resource +
                                '&redirect_uri=' + redirectUri +
                                '&state=' + state + 
                                '&prompt=login';
        
        res.redirect(userAuthorizationUrl);
    });
    
});

app.get('/login', function (req, res) {
    console.log(req.cookies);
    
    res.cookie('acookie', 'this is a cookie');
    
    res.send('\
<head>\
  <title>Show AD Users Http response </title>\
</head>\
<body>\
  <a href="./auth">Login(Admin)</a><br><a href="./authuser">Login(user)</a>\
</body>\
    ');
});

//Oauth callback
app.get('/getAToken', function (req, res) {
    
    var token_request = 'code=' + req.query.code +
                        '&client_id=' + clientId +
                        '&client_secret=' + clientSecret +
                        '&redirect_uri=' + redirectUri +
                        '&grant_type=authorization_code';
    
    
    var request_length = token_request.length;
    console.log("requesting: " + token_request);
    
    //token request
    
    request(
        {
            method: 'POST',
            headers: { 'Content-length': request_length, 'Content-type': 'application/x-www-form-urlencoded' },
            uri: tokenEndpoint,
            body: token_request
        },
        function (error, response, bodyp) {
            if (response.statusCode == 200) {
                bodyp = JSON.parse(bodyp);
                
                //response with token
                var decoded = jwt.decode(bodyp.access_token);
                console.log(' jwt.decode(bodyp.access_token)', decoded);
                
                request(
                    {
                        method: 'GET',
                        headers: { 'Authorization': 'bearer ' + bodyp.access_token, 'Content-type': 'application/x-www-form-urlencoded' },
                        uri: resource + '/' + decoded.tid + '/users?api-version=1.5'
                                
                    }    ,
            function (error, response, body) {
                        console.log('----response----: ', response);
                        
                        if (error) {
                            console.log(body);
                            res.send(JSON.stringify(response));
                        }
                        else {
                            console.log(body);
                            res.send(JSON.stringify(response));
                        }
                    }
                );
                       
            }
            else {
                
                res.send(body);
                         
            }
        }
    );
});












// catch 404 and forward to error handler
app.use(function (req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function (err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});



app.listen(process.env.port || 3000);

module.exports = app;
