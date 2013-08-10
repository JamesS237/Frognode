var sqlite = require('sqlite3');
var cryptico = require('cryptico');
var xmlrpc = require('xmlrpc');
var express = require('express');

var app = express();
var spawn = require('child_process').spawn,
    bitmessage    = spawn('python', ['src/bitmessagemain.py']);

debugBitmessage = false;
if (debugBitmessage) {
	bitmessage.stderr.on('data', function (data) {
  	  console.log('stderr: ' + data);
	});
	bitmessage.stdout.on('data', function(data) {
		console.log('stdout: ' + data);
	});
	bitmessage.on('close', function(code, signal) {
		console.log('Bitmessage daemon killed.');
	});
}

var db = new sqlite.Database('node.sqlite');
//inital setup
db.serialize(function() {
	db.run('create table if not exists Users (pubkey TEXT)');
	db.run('create table if not exists Addresses (address TEXT, label TEXT, userid INTEGER)');
});
var node_secret = '123';
var nodeRSA = cryptico.generateRSAKey(node_secret, 1024);
var nodeRSAPubkey = cryptico.publicKeyString(nodeRSA);

console.log(nodeRSAPubkey);


var rpcClient = xmlrpc.createClient({
	host: 'localhost',
	port: 8442,
	basic_auth: {
		user: 'Frog',
		pass: 'testpass'
	}
});

var started;
var add = function() {
	rpcClient.methodCall('add', [1,2], function(err, val) {
	  if (val == 3) {
	  	started = true;
	  }
	  if (started) {
	  	console.log('Bitmessage daemon successfully started.');
	  }
	});
}

//give pybitmessage time to start up
setTimeout(add, 1000);

//utility functions
function isValidPubkey(pubkey) {
	if (pubkey == undefined) {
		return false;
	}
	if (pubkey.length < 5) {
		return false;
	}
	regexPattern = /^[a-zA-Z0-9\=\+\/]+$/;
	return regexPattern.test(pubkey);
}
function decryptIncoming(data) {
	try	{
		var cleartext = cryptico.decrypt(data, nodeRSA);
	} catch (e) {
		return 'Failed to decrypt request.';
	}
	if (cleartext.signature == 'verified') {
		return {plaintext: cleartext.plaintext, pubkey: cleartext.publicKeyString};
	} else {
		return 'Signature invalid.';
	}
}
function encryptOutgoing(data, key) {
	var jsonString = JSON.stringify(data);
	var encrypted = cryptico.encrypt(jsonString, key, nodeRSA);
	var json = {data: encrypted.cipher};
	return JSON.stringify(json);
}

//main program
//note: send decrypted data when the message is a crypto error. encrypt all other times.
var main = function() {
	if (started) {
		app.use(express.bodyParser());
		app.post('/newaddress', function(req, res) {
			res.header("Access-Control-Allow-Origin", "*");
			var data = req.body.data;
			var decryptedData = decryptIncoming(data);

			if (decryptedData == 'Failed to decrypt request.' || decryptedData == 'Signature invalid.') {
				result.error = "Invalid message.";
				res.send(JSON.stringify(result));
			}

		});
		app.post('/newuser', function(req, res) {
			res.header("Access-Control-Allow-Origin", "*"); //ok, sure whatever
			var result = {};
			function doesNotExist(key) {
				function successSql() {
					result.message = 'Successfully inserted pubkey.';
					toSend = encryptOutgoing(result, decryptedData.pubkey);
					res.send(toSend);
				}
				stmt = db.prepare('insert into Users (pubkey) values (?)');
				stmt.run(key, function(err){
					successSql();
				});
			}
			var data = req.body.data;
			var decryptedData = decryptIncoming(data);
			if (decryptedData == 'Failed to decrypt request.' || decryptedData == 'Signature invalid.') {
				result.error = "Invalid message.";
				res.send(JSON.stringify(result));
			}
			decryptedData = JSON.parse(decryptedData.plaintext);
			pubkey = decryptedData.pubkey;

			if (isValidPubkey(pubkey)) {
				stmt = db.prepare('select count(*) from Users where pubkey=(?)');
				stmt.get(pubkey, function(err, row) {
					if (err) {
						console.log(err);
					}
					if (row['count(*)'] == 0) {
						doesNotExist(pubkey);
					} else {
						result.message = 'That key is already in use.';
						toSend = encryptOutgoing(result, decryptedData.pubkey);
						res.send(toSend);
					}
				});
			} else {
				result.error = "That key is invalid.";
				res.send(JSON.stringify(result));
			}
		});

		app.listen(1455);
		console.log('listening on port 1455');
	} else {
		console.log('Bitmessage daemon not responding. Killing server.');
		process.exit();
	}
}
// .1 seconds after giving pybitmessage time, start up web server.
setTimeout(main, 1100);

process.on('SIGINT', function() {
  console.log("\ngracefully shutting down from  SIGINT (Crtl-C)");
  console.log('Killing Bitmessage daemon');
  bitmessage.kill();
  process.exit();
});