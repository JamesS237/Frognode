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
setTimeout(add, 1500);

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
function decryptRequest(data, res) {
	var decryptedData = decryptIncoming(data);
	if (decryptedData == 'Failed to decrypt request.' || decryptedData == 'Signature invalid.') {
		result = {error: 'Invalid message.'};
		res.send(JSON.stringify(result));
	} else {
		var decryptedData = {data: JSON.parse(decryptedData.plaintext), pubkey: decryptedData.pubkey};
		return decryptedData;
	}
}
function encryptOutgoing(data, key) {
	var jsonString = JSON.stringify(data);
	var encrypted = cryptico.encrypt(jsonString, key, nodeRSA);
	var json = {data: encrypted.cipher};
	return JSON.stringify(json);
}
function setGlobalHeaders(res) {
	res.header("Access-Control-Allow-Origin", "*"); //ok, sure whatever
}
function keyIDCheck(keyID, key, callback) {
	//get address
	function sqlDone(row) {
		if (row['pubkey'] == key) {
			callback(true);
		} else {
			callback(false);
		}
	}
	stmt = db.prepare('select pubkey from Users where rowid=(?)');
	stmt.get(keyID, function(err, row) {
		sqlDone(row);
	});
}
//main program
//note: send decrypted data when the message is a crypto or signing error. encrypt all other times.
var main = function() {
	if (started) {
		app.use(express.bodyParser());
		app.post('/newaddress', function(req, res) {
			setGlobalHeaders(res);
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res);
			var dData = decryptedData.data;

			keyID = dData.kid;

			function keyIDValid(valid) {

			}
			keyIDCheck(keyID, pubkey, keyIDValid);
		});
		app.post('/getaddresses', function(req, res) {
			setGlobalHeaders(res);
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res);
			var dData = decryptedData.data;
			keyID = dData.kid;

			function keyIDValid(valid) {
				function sqlDone(rows) {
					result = {addresses: rows};
					toSend = encryptOutgoing(result, decryptedData.pubkey);
					res.send(toSend);
				}
				if (valid) {
					stmt = db.prepare('select * from Addresses where userid=(?)');
					stmt.all(keyID, function(err, rows) {
						sqlDone(rows);
					});
				} else {
					result = {error: 'Your signing key didn\'t match the keyID.'};
					res.send(JSON.stringify(result));
				}
			}
			keyIDCheck(keyID, pubkey, keyIDValid);

		});
		app.post('/getmessage', function(req, res) {
			setGlobalHeaders(res);
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res);
			var dData = decryptedData.data;

			var msgId = dData.msgid;

		});
		app.post('/getinbox', function(req, res) {
			console.log('getinbox request');
			setGlobalHeaders(res);
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res);
			var dData = decryptedData.data;
			var pubkey = decryptedData.pubkey;

			function sqlDone(addresses) {
				var decodedMessages = [];
				for (var i = 0; i < addresses.length; i++) {
					rpcClient.methodCall('getInboxMessagesByAddress', [addresses[i].address], function(err, val) {
						messages = JSON.parse(val);
						for (var i = 0; i < data.inboxMessages.length; i++) {
							decodedMessage = data.inboxMessages[i];
							decodedMessage.subject = new Buffer(data.inboxMessages[i].subject, 'base64').toString('ascii');
							decodedMessage.message = new Buffer(data.inboxMessages[i].message, 'base64').toString('ascii');
							decodedMessages.push(decodedMessage);
						}

					});
				}
				result = {messages: decodedMessages};
				toSend = encryptOutgoing(result, decryptedData.pubkey);
				res.send(toSend);
			}
			var keyID = dData.kid;
			function keyIDValid(valid) {
				if (valid) {
					stmt = db.prepare('select * from Addresses where userid=(?)');
					stmt.all(keyID, function(err, rows) {
						sqlDone(rows);
					});
				} else {
					result = {error: 'Your signing key didn\'t match the keyID.'};
					res.send(JSON.stringify(result));
				}
			}
			keyIDCheck(keyID, pubkey, keyIDValid);

		});
		app.post('/newuser', function(req, res) {
			setGlobalHeaders(res);
			function doesNotExist(key) {
				function successSql() {
					function returnKeyWithId(id) {
						result = {kid: id['last_insert_rowid()'], message: 'Successfully inserted pubkey.'}
						toSend = encryptOutgoing(result, decryptedData.pubkey);
						res.send(toSend);
					}
					db.get('select last_insert_rowid()', function(err, row) {
						returnKeyWithId(row)
					});
				}
				stmt = db.prepare('insert into Users (pubkey) values (?)');
				stmt.run(key, function(err){
					successSql();
				});
			}
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res);
			var pubkey = decryptedData.pubkey;

			if (isValidPubkey(pubkey)) {
				stmt = db.prepare('select rowid from Users where pubkey=(?)');
				stmt.get(pubkey, function(err, row) {
					if (err) {
						console.log(err);
					}
					if (row == undefined) {
						doesNotExist(pubkey);
					} else {
						result = {message: 'That key is already in use.', kid: row['rowid']}
						toSend = encryptOutgoing(result, decryptedData.pubkey);
						res.send(toSend);
					}
				});
			} else {
				result = {error: 'That key is invalid.'}
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
setTimeout(main, 1600);

process.on('SIGINT', function() {
  console.log("\ngracefully shutting down from  SIGINT (Crtl-C)");
  console.log('Killing Bitmessage daemon');
  bitmessage.kill();
  process.exit();
});