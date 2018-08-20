var bodyParser = require('body-parser');
var express = require('express');
var app = express();
app.use(bodyParser.json()); // support json encoded bodies
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies
app.get('/post.js', function(req, res) {
  res.writeHead(200, {'Content-Type': 'text/html'});	
  res.write('<html><body><form action="/post.js" method="post"><div>Username:</div><input type="text" id="username" name="username"/><br/><div>Password:</div><input type="text" id="password" name="password"/><br/><input type="submit" value="Send credentials"></form></body></html>');
  res.send('noResponse</br>');
});
app.listen(3001);
app.post('/post.js', function(req, res) {
  var resp = eval(req.body.username);
  res.send('Response</br>'+resp);
});
app.listen(3003);

