var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var client = require('redis').createClient();
var rsa = require('node-rsa');
var crypto = require('crypto');
var myKey = null;
var fs = require('fs');
var https = require('https');
var masterPin = process.env.npm_package_config_masterPin;

var config = {
  'debugUnlock': process.env.npm_package_config_debugUnlock == 'true'
                || process.env.npm_package_config_debugAll == 'true',
  'debugPinChange': process.env.npm_package_config_debugUnlock == 'true'
                || process.env.npm_package_config_debugAll == 'true',
  'debugRegistration': process.env.npm_package_config_debugUnlock == 'true'
                || process.env.npm_package_config_debugAll== 'true',
  'defaultStatus' : process.env.npm_package_config_noApproval == 'true' ? 0 : -1,
  'debugSignature': process.env.npm_package_config_debugSignature == 'true'
                || process.env.npm_package_config_debugAll== 'true',
  'debugRateLimiting': process.env.npm_package_config_debugRateLimiting == 'true'
                || process.env.npm_package_config_debugAll== 'true',
  'logRequests' : process.env.npm_package_config_logRequests == 'true'
};

var middleware = require('./middleware')(config);

app.use(bodyParser.json());

if(config.logRequests){
  console.log("Set to log *all* requests to console, this will print a lot out!");
  app.use(middleware.debug);
}

app.post('/registration_1', function(req, res){
  if(config.debugRegistration);
   console.log('Registration 1: Entering registration 1 code');
  var pubKey = req.body.pubKey;
  var fingerprint = req.body.fingerprint;
  if(!fingerprint){
    if(config.debugRegistration) console.log('Registration 1: Either the request was missing fingerprint!');
    res.status(400).end();
    return;
  }


  // Ensure this key hasn't been used before
  client.hget('pubKeys', fingerprint, function(error, data){
    if(error || data){
      if(config.debugRegistration) console.log('Registration 1: This key has been registered before, ending connection!');
      res.status(400).end();
      return;
    }else{
      var prime = crypto.getDiffieHellman('modp18').getPrime();
      if(config.debugRegistration) console.log('Registration 1: First 10 hex of the prime are 0x'
                                                + prime.toString('hex').slice(0,10) + ' , length: ' + prime.length);
      var dhPair = crypto.createDiffieHellman(prime);
      dhPair.generateKeys();
      var publicDH = dhPair.getPublicKey('hex');
      var myPrivDH = dhPair.getPrivateKey('hex');
      client.hset('pubKeys', fingerprint, JSON.stringify({'fingerprint': fingerprint, 'status': -2, 'key': pubKey, 'DHPub': publicDH, 'DHPriv': myPrivDH, 'DHPrime': prime }), function(error, data){
        if(data == 1){
          if(config.debugRegistration) console.log('Registration 1: Success, sending the values over to you!');
          res.send({
            'pubkey': myKey.exportKey('public'),
            'DHPub': publicDH,
            'DHPrime': prime.toString('hex')
          });
        }
      });
    }

  });
});

app.post('/registration_2', middleware.fingerprint,
    function(req, res){
  // Validate inputs existance and correctness
  var otherDH = req.body.DHPub;
  if(config.debugRegistration) console.log('Registration 2: Now entering registration 2 code!');
  if(!otherDH){
    res.status(400).end();
    if(config.debugRegistration) console.log('Registration 2: Missing DHPub!');
    return;
  }
  try{
    if(req.widget.status != -2){
      if(config.debugRegistration) console.log('Registration 2: Widget is at wrong status (probably already registered), ending!');
      res.status(403).end();
      return;
    }
    var myDHPriv = new Buffer(req.widget.DHPriv, 'hex')
    var myDHPub = new Buffer(req.widget.DHPub, 'hex')
    var myDHPrime = new Buffer(req.widget.DHPrime, 'hex');
    var myDH = crypto.createDiffieHellman(myDHPrime);
    myDH.setPublicKey(myDHPub);
    myDH.setPrivateKey(myDHPriv);
    var otherDH = new Buffer(otherDH, 'hex');
    req.widget.sharedSecret = crypto.createHash('sha256').update(myDH.computeSecret(otherDH).toString('hex')).digest().toString('hex');
    if(config.debugRegistration) console.log('Registration 2: Shared secret generated, first 10 hex bytes: 0x'
                                              + req.widget.sharedSecret.slice(0,10) + ' , length: ' + req.widget.sharedSecret.length/2);
    req.widget.status = config.defaultStatus;
    if(config.debugRegistration) console.log('Registration 2: Widget has been set to status: ' + req.widget.status);
    req.widget.hash = crypto.createHash('sha256').update('000000').digest('hex');
    req.widget.masterHash = crypto.createHash('sha256').update(masterPin).digest('hex');
    client.hset('pubKeys', req.widget.fingerprint, JSON.stringify(req.widget));
    res.send({'confirmed': 1}).end();
    if(config.debugRegistration) console.log('Registration 2: Registration confirmed!');
    if(config.debugRegistration && req.widget.status == 0) console.log('Registration 2: Widget is ready to be used, no need to modify files.');
    if(config.debugRegistration && req.widget.status == -1) console.log('Registration 2: Widget file needs to be modified before use of this widget.');
    fs.appendFile('requested-widgets.txt', JSON.stringify({'fingerprint': req.widget.fingerprint,
                                                            'flag':''}) + '\n');
  }catch(e){
    if(config.debugRegistration) console.log('Registration 2: Failed out with error: ' + e);
    res.send({'confirmed': 0}).end();
  }
});

app.post('/start_unlock', middleware.fingerprint, middleware.rateLimiting, function(req, res){
  if(config.debugUnlock) console.log('Start Unlock: You are now in start unlock!');
  if(req.widget.status == 0){
    req.widget.currUnlock = crypto.randomBytes(32).toString('hex');
    req.widget.save(req.widget);
    if(config.debugUnlock) console.log('Start Unlock: Challenge is being sent, hex value is: 0x' + req.widget.currUnlock);
    res.send({'challenge': req.widget.currUnlock});
  }else{
    if(config.debugUnlock) console.log('Start Unlock: Your widget was not at the right status, did you forget to modify the registered-widgets.txt?');
    res.status(403).end();
    return;
  }
});

app.post('/unlock', middleware.fingerprint, middleware.rateLimiting, function(req, res){
  if(config.debugUnlock) console.log('Unlock: You are now in unlock!');
  if(req.widget.status == 0){
    if(req.widget.currUnlock == ''){
      if(config.debugUnlock) console.log('Unlock: There was no challenge saved for you, did you call start_unlock?');
      res.status(400).end();
      return;
    }
    var chal = new Buffer(req.widget.currUnlock, 'hex');
    var verify = crypto.createHmac('sha256', new Buffer(req.widget.sharedSecret, 'hex'))
                 .update(new Buffer(chal, 'hex'))
                 .update(new Buffer(req.widget.hash, 'hex'))
                 .digest('hex');
    if(config.debugUnlock) console.log('Unlock: Expected hash value is: ' + verify);
    if(config.debugUnlock) console.log('Unlock: Received hash value is: ' + req.body.hash);
    req.widget.currUnlock = '';
    req.widget.save(req.widget);
    if(verify == req.body.hash){
      var flag = req.widget.flag || "flagtext";
      if(config.debugUnlock) console.log('Unlock: The hashes match! sending success=1, and flag=' + flag);
      res.send({'success': 1, 'flag': flag});
      return;
    }else{
      if(config.debugUnlock) console.log('Unlock: The hashes did not match! sending success=0 :(');
      res.status(400).send({'success': 0}).end();
      return;
    }
  }
  if(config.debugUnlock) console.log('Unlock: Your widget is not fully registered yet. Did you miss a step?');
  res.status(400).end();
  return;
});

app.post('/start_pin_change', middleware.fingerprint, middleware.rateLimiting, function(req, res){
  if(config.debugPinChange) console.log('Start Pin Change: You are now in start pin change!');
  if(req.widget.status == 0){
    req.widget.currPinChange = crypto.randomBytes(32).toString('hex');
    if(config.debugPinChange) console.log('Start Pin Change: Now sending the challenge: ' + req.widget.currPinChange);
    req.widget.save(req.widget);
    res.send({'challenge': req.widget.currPinChange}).end();
  }else{
    if(config.debugPinChange) console.log('Start Pin Change: Your widget is not fully registered, did you miss a step?');
    res.status(403).end();
    return;
  }
});

app.post('/pin_change', middleware.fingerprint, middleware.rateLimiting,
  function(req, res){
  if(config.debugPinChange) console.log('Pin Change: You are now in Pin Change!');
  var chal = new Buffer(req.widget.currPinChange, 'hex');

  if(config.debugPinChange) console.log('Pin Change: Challenge is: ' + chal.toString('hex'));
  req.widget.currPinChange = '';
  req.widget.save(req.widget);
  try{
    if(req.widget.status == 0){
      var retrievedHash = undefined;
      try{
        if(config.debugPinChange) console.log('Pin Change: Now trying master pin verification...');
        var masterHash = new Buffer(req.widget.masterHash, 'hex');
        var hash = [];
        for(i = 0; i < chal.length; i++){
          hash.push(chal[i]^masterHash[i]);
        }
        var hash = crypto.createHash('sha256').update(new Buffer(hash)).digest();
        if(hash.toString('hex') != req.body.hash.slice(64)){
          throw new Error("Invalid");
        }
        var hmac = crypto.createHmac('sha256', new Buffer(req.widget.sharedSecret, 'hex')).update(masterHash).digest();
        var otherHmac = new Buffer(req.body.hash.slice(0,64),'hex');
        var newHash = [];
        for(i = 0; i < hmac.length; i++){
          newHash.push(hmac[i] ^ otherHmac[i]);
        }
        newHash = new Buffer(newHash).toString('hex');
        if(config.debugPinChange) console.log('Pin Change: challenges match, detected correct master pin entry!');
        if(config.debugPinChange) console.log('Pin Change: changed to: ' + newHash);

      } catch(e){
        var masterHash = new Buffer(req.widget.hash, 'hex');
        var hash = [];
        for(i = 0; i < chal.length; i++){
          hash.push(chal[i]^masterHash[i]);
        }
        var hash = crypto.createHash('sha256').update(new Buffer(hash)).digest();
        if(hash.toString('hex') != req.body.hash.slice(64)){
          res.status(400).end();
          return;
        }
        var hmac = crypto.createHmac('sha256', new Buffer(req.widget.sharedSecret, 'hex')).update(masterHash).digest();
        var otherHmac = new Buffer(req.body.hash.slice(0,64),'hex');
        var newHash = [];
        for(i = 0; i < hmac.length; i++){
          newHash.push(hmac[i] ^ otherHmac[i]);
        }
        newHash = new Buffer(newHash).toString('hex');
        if(config.debugPinChange) console.log('Pin Change: challenges match, detected correct tenant pin entry!');
        if(config.debugPinChange) console.log('Pin Change: changed to: ' + newHash);
      }
      req.widget.hash = newHash;
      if(config.debugPinChange) console.log('Pin Change: now updating tenant pin hash to: ' + newHash);
      req.widget.save(req.widget);
      if(config.debugPinChange) console.log('Pin Change: Sending success=1!');
      res.send({success: 1});

    }else{
      if(config.debugPinChange) console.log('Pin Change: widget is not fully registered!');
      res.status(403).send({success: 0}).end()
      return;
    }
  }catch(e){
    if(config.debugPinChange) console.log(e);
    if(config.debugPinChange) console.log('Pin Change: Challenges do not match, implies pin was incorrect, ending!');
    res.status(400).end();
    throw(e);
    return;
  }
});

// Initialize the database and server with keys
function init(done){
  // Check if my key exists
  client.hget('mykey', 'private', function(error, data){
    // If it does, restore it from the database
    if(data){
      myKey = new rsa(data);
      var registered = fs.readFileSync('registered-widgets.txt').toString().split("\n");
      registered.forEach(function(i, index, registered){
        try{
          var widget = JSON.parse(i);
          client.hget('pubKeys', widget.fingerprint, function(error, data){
            if(data){
              data = JSON.parse(data);
              data.status = 0;
              data.flag = widget.flag;
              client.hset('pubKeys', widget.fingerprint, JSON.stringify(data));
            }
          });
        }catch(e){
        }
        if(index == registered.length - 1){
          done();
        }
      });
    }else{
      // Otherwise FLUSH the database and create a new keypair.
      fs.stat('registered-widgets.txt', function(err, stats){
        if(err){
          fs.appendFile('registered-widgets.txt','');
          init(done);
          return;
        }if(stats.size > 0){
          fs.unlink('registered-widgets.txt');
        }
        fs.unlink('requested-widgets.txt', function(err){

        });
        myKey = new rsa();
        myKey.generateKeyPair();
        client.flushall(function(error, data){
          client.hset('mykey', 'private', myKey.exportKey(), function(error, data){
            done();
          });
        });
      });
    }
  });
}

// Check if running in testing environment
if(require.main == module){
	init(function(){
	   app.listen(5000);
     console.log("Now Listening on Port 5000....");
   });
}

module.exports.init = init;
module.exports.getApp = app;
