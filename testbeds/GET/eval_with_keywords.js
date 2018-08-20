var express = require('express');
var app = express();
app.get('/', function(req, res) {
 var resp=eval(req.query.name);
 res.send('Output ReferenceError SyntaxError </br>'+resp);
});
app.listen(3002);

