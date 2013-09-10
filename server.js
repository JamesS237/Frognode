var sqlite = require('sqlite3');
var cryptico = require('cryptico');
var xmlrpc = require('xmlrpc');
var express = require('express');

var app = express();

var db = new sqlite.Database('node.sqlite');
//inital setup
db.serialize(function() {
	db.run('create table if not exists Users (pubkey TEXT)');
	db.run('create table if not exists Addresses (address TEXT, label TEXT, userid INTEGER)');
	db.run('create table if not exists UsedNonces (nonce INTEGER)');
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

function checkBitmessaged() {
	rpcClient.methodCall('add', [1,2], function(err, val) {
	  	if (val == 3) {
	  		main(true);
	  	}
	});
}

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
function fromBase64(string) {
	result = new Buffer(string, 'base64').toString('ascii');
	return result;
}
function toBase64(string) {
	result = new Buffer(string).toString('base64');
	return result;
}
function checkIfNonceUnused(nonce, callback, request) { //also insert in db
	function insertNonce(nonce) {
		stmt = db.prepare('insert into UsedNonces (nonce) values (?)');
		stmt.run(nonce, callback);
	}
	stmt = db.prepare('select exists(select 1 from UsedNonces where nonce=(?) limit 1)');
	stmt.get(nonce, function(err, row) {
		if (row['exists(select 1 from UsedNonces where nonce=(?) limit 1)'] == 0 && !err) {
			insertNonce(nonce);
		} else {
			console.log('used nonce!');
			result = {error: 'nonce already used'};
			request.send(JSON.stringify(result));
		}
	});
}
//main program
//note: send decrypted data when the message is a crypto or signing error. encrypt all other times.
function main(BitmessageStatus) {
	if (BitmessageStatus == true) {
		app.use(express.bodyParser());
		app.post('/sendmessage', function(req, res) {
			//todo: do this
		});
		app.post('/newaddress', function(req, res) {
			console.log('newaddress request');
			setGlobalHeaders(res);
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res);
			var dData = decryptedData.data;

			keyID = dData.kid;
			label = dData.label;
			keySeed = dData.seed;

			function insertAddress(address, label, keyID) {
				 stmt = db.prepare('insert into Addresses (address, label, userid) values (?, ?, ?)');
				 values = [address, label, keyID];
				 stmt.run(values, function(err){
				 });

				 result = {status: 'done'};
				 toSend = encryptOutgoing(result, decryptedData.pubkey);
				 res.send(toSend);
			}
			function nonceUnused() {
				function keyIDValid(valid) {
					if (valid) {
						seedBase64 = toBase64(keySeed);
						rpcClient.methodCall('createDeterministicAddresses', [seedBase64], function(err, val) {
							if (err == null) {
								var value = JSON.parse(val);
								insertAddress(value.addresses[0], label, keyID);
							}
						});
					} else {
						result = {error: 'Your signing key didn\'t match the keyID.'};
						res.send(JSON.stringify(result));
					}
				}
				keyIDCheck(keyID, pubkey, keyIDValid);
			}
			checkIfNonceUnused(dData.nonce, nonceUnused, res);
		});
		app.post('/getaddresses', function(req, res) {
			console.log('getaddresses request');
			setGlobalHeaders(res);
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res);
			var dData = decryptedData.data;

			keyID = dData.kid;

			function nonceUnused() {
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
			}
			checkIfNonceUnused(dData.nonce, nonceUnused, res);
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
				function sendInbox(messages) {
					result = {messages: messages};
					toSend = encryptOutgoing(result, pubkey);
					res.send(toSend);
				}
				var requestCounter = 0;
				for (var i = 0; i < addresses.length; i++) {
					rpcClient.methodCall('getInboxMessagesByAddress', [addresses[i].address], function(err, val) {
						requestCounter += 1;
						messages = JSON.parse(val);
						for (var i = 0; i < messages.inboxMessages.length; i++) {
							decodedMessage = {};
							decodedMessage.subject = fromBase64(messages.inboxMessages[i].subject);
							decodedMessage.message = fromBase64(messages.inboxMessages[i].message);
							decodedMessage.toAddress = messages.inboxMessages[i].toAddress;
							decodedMessage.fromAddress = messages.inboxMessages[i].fromAddress;
							decodedMessage.timeReceived = messages.inboxMessages[i].receivedTime;
							decodedMessages.push(decodedMessage);
						}
						if (requestCounter == addresses.length) {
							sendInbox(decodedMessages);
						}
					});
				}
			}
			var keyID = dData.kid;
			function nonceUnused() {
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
			}
			checkIfNonceUnused(dData.nonce, nonceUnused, res);
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
			var dData = decryptedData.data;
			var pubkey = decryptedData.pubkey;

			function nonceUnused() {
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
			}
			checkIfNonceUnused(dData.nonce, nonceUnused, res);
		});

		app.listen(1455);
		console.log('listening on port 1455');
	} else {
		console.log('Bitmessage daemon not responding. Killing server.');
		process.exit();
	}
}

checkBitmessaged();