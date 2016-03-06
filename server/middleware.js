var client = require('redis').createClient();
var rsa = require('node-rsa');
var crypto = require('crypto');
var config = {};
middleware = {};
middleware.signedData = function(req, res, next){
  if(config.debugSignature) console.log('Signature: Now in signature verification code');
  var data = req.body.data;
  var sig = req.body.signature;
  var key = new rsa(req.widget.key);
  console.log(key.exportKey('public'));
  try{
    if(key.verify(data, sig, 'utf8', 'utf8')){
      if(config.debugSignature) console.log('Signature: Verification succeeded!');
      req.body = JSON.parse(data);
      next();
      return;
    }else{
      if(config.debugSignature) console.log('Signature: Verification failed!');
      res.sendStatus(400);
    }
  }catch(e){
    if(config.debugSignature) console.log('Signature: Failed, something was not valid');
    res.sendStatus(400);
  }
};

middleware.fingerprint = function(req, res, next){
  var fingerprint = req.body.fingerprint;
  if(fingerprint){
    client.hget('pubKeys', fingerprint, function(error, data){
      if(data){
        req.widget = JSON.parse(data);
        req.widget.save = (toSave) => {
          client.hset('pubKeys', toSave.fingerprint, JSON.stringify(toSave));
          console.log("Found widget!");
        };
        next();
        return;
      }else{
        res.sendStatus(400).end();
        return;
      }
    });
  }else{
    res.sendStatus(400).end();
  }
};

middleware.rateLimiting = function(req, res, next){
  if(req.widget.lockoutTime && req.widget.lockoutCount){
    var time = new Date().getTime() - req.widget.lockoutTime;
    if(time < 3600000 && req.widget.lockoutCount >= 60){
      if(config.debugRateLimiting) console.log('Rate Limiting: Blocked due to rate limiting');
      res.sendStatus(420).end(); // Smoke Weed
      return;
    }
  }
  var actual = res.status;
  res.status = (statusCode) => {
    res.status = actual;
    if(statusCode >= 400 && statusCode < 500){
      var currTime = new Date().getTime();
      if(currTime - req.widget.lockoutTime < 3600000){
        req.widget.lockoutCount += 1;
      }else{
        req.widget.lockoutCount = 1;
        req.widget.lockoutTime = currTime;
      }
      req.widget.save(req.widget);
    }
    if(config.debugRateLimiting) console.log('Rate Limiting: Bad request received and logged, currently at '
                                              + req.widget.lockoutCount + '/60');
    res.status(statusCode);
    return res;
  };
  next();
};

middleware.debug = function(req, res, next){
  console.log(req.method + " " + req.originalUrl + "\n\t{");
  for (var key in req.body) {
    if (req.body.hasOwnProperty(key)) {
      console.log("\t\t" + key + ": " + req.body[key] + ",");
    }
  }
  console.log("\n\t}");
  next();
};

module.exports = function(newConfig){
  config = newConfig;
  return middleware;
};
