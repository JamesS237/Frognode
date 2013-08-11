var sqlite = require('sqlite3'),
    cryptico = require('cryptico'),
    xmlrpc = require('xmlrpc'),
    express = require('express');

var app = express();
var spawn = require('child_process').spawn,
    bitmessage = spawn('python', ['src/bitmessagemain.py']);

var debugBitmessage = false;
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
};

//give pybitmessage time to start up
setTimeout(add, 1000);

//utility functions
function isValidPubkey(pubkey) {
	if (pubkey === undefined) {
		return false;
	}
	if (pubkey.length < 5) {
		return false;
	}
	var regexPattern = /^[a-zA-Z0-9\=\+\/]+$/;
	return regexPattern.test(pubkey);
}
function decryptIncoming(data) {
	try	{
		var cleartext = cryptico.decrypt(data, nodeRSA);
        if (cleartext.signature == 'verified') {
            return {plaintext: cleartext.plaintext, pubkey: cleartext.publicKeyString};
        } else {
            return 'Signature invalid.';
        }
	} catch (e) {
		return 'Failed to decrypt request.';
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
//main program
//note: send decrypted data when the message is a crypto error. encrypt all other times.
var main = function() {
	if (started) {
		app.use(express.bodyParser());
		app.post('/newaddress', function(req, res) {
			setGlobalHeaders(res);
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res).data;
		});
		app.post('/getaddresses', function(req, res) {

		});
		app.post('/getinbox', function(req, res) {
			setGlobalHeaders(res);
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res);
			var dData = decryptedData.data;

			function sqlDone(addresses) {
				function rpcDone(data) {
					var decodedMessages = [];
					for (var i = 0; i < data.inboxMessages.length; i++) {
						var decodedMessage = data.inboxMessages[i];
						decodedMessage.subject = new Buffer(data.inboxMessages[i].subject, 'base64').toString('ascii');
						decodedMessage.message = new Buffer(data.inboxMessages[i].message, 'base64').toString('ascii');
						decodedMessages.push(decodedMessage);
					}
					var result = {messages: decodedMessages};
					var toSend = encryptOutgoing(result, decryptedData.pubkey);
					res.send(toSend);
				}
				for (var i = 0; i < addresses.length; i++) {
                    rpcClient.methodCall('getInboxMessagesByAddress', [addresses[i].address], function(err, val) {
						rpcDone(JSON.parse(val));
					});
				}
			}
			var keyID = dData.kid;
			var stmt = db.prepare('select * from Addresses where userid=(?)');
			stmt.all(keyID, function(err, rows) {
				sqlDone(rows);
			});
		});
		app.post('/newuser', function(req, res) {
			setGlobalHeaders(res);
			function doesNotExist(key) {
				function successSql() {
					function returnKeyWithId(id) {
						var result = {kid: id['last_insert_rowid()'], message: 'Successfully inserted pubkey.'};
						var toSend = encryptOutgoing(result, decryptedData.pubkey);
						res.send(toSend);
					}
					db.get('select last_insert_rowid()', function(err, row) {
						returnKeyWithId(row)
					});
				}
				var stmt = db.prepare('insert into Users (pubkey) values (?)');
				stmt.run(key, function(err){
					successSql();
				});
			}
			var data = req.body.data;
			var decryptedData = decryptRequest(data, res).data;
			var pubkey = decryptedData.pubkey;

			if (isValidPubkey(pubkey)) {
				var stmt = db.prepare('select rowid from Users where pubkey=(?)');
				stmt.get(pubkey, function(err, row) {
					if (err) {
						console.log(err);
					}
					if (row == undefined) {
						doesNotExist(pubkey);
					} else {
						var result = {message: 'That key is already in use.', kid: row['rowid']}
						var toSend = encryptOutgoing(result, decryptedData.pubkey);
						res.send(toSend);
					}
				});
			} else {
				var result = {error: 'That key is invalid.'}
				res.send(JSON.stringify(result));
			}
		});

		app.listen(1455);
		console.log('listening on port 1455');
	} else {
		console.log('Bitmessage daemon not responding. Killing server.');
		process.exit();
	}
};
// .1 seconds after giving pybitmessage time, start up web server.
setTimeout(main, 1100);

process.on('SIGINT', function() {
    console.log("\ngracefully shutting down from  SIGINT (Crtl-C)");
    console.log('Killing Bitmessage daemon');
    bitmessage.kill();
    process.exit();
});