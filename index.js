
var net = require('net');
var TLSHeader = require('tls-header');
var Handshake = require('tls-handshake').Handshake;
var HelloMessage = require('tls-handshake').HelloMessage;
var constants = require('tls-constants');

function TLSRequest(port, host) {
  this.socket = net.connect(port, host, this._onsocketConnected.bind(this));
  this.socket.on('data', this._ondata.bind(this));
  this.socket.on('error', this._onerror.bind(this));
  this.socket.on('close', this._onclose.bind(this));
}

TLSRequest.prototype._onsocketConnected = function() {
  var message = Object.create(TLSHeader);
  message.version = '1.1';
  message.type = 'handshake';

  var hello = Object.create(HelloMessage);
  var handshake = Object.create(Handshake);
  handshake.type = 'client_hello';
  handshake.body = hello;
  message.body = handshake.toBuffer();

  var buf = message.toBuffer();
  console.log(buf);
  this.socket.write(buf);
};

TLSRequest.prototype._ondata = function(chunk) {
  console.log(chunk);
  var type = constants.TLS.ContentTypes[chunk[0]];
  var version = matchVersion();
  var length = chunk.readUInt16BE(3);
  var fragment = chunk.slice(5, 5 + length);

  // parse type
  if (type === 'alert') {
    parseAlert(fragment);
  }

  function matchVersion() {
    var versions = constants.TLS.Versions;
    for (var ver in versions) {
      var item = versions[ver];
      if (item[0] === chunk[1] && item[1] === chunk[2]) {
        return ver;
      }
    }
  }

  function parseAlert(fragment) {
    var level = constants.alert.level[fragment[0]];
    var description = constants.alert.description[fragment[1]];
    switch (level) {
      case 'warning':
        console.error(description);
        break;
      case 'fatal':
        throw new Error(description);
      default:
        break;
    }
  }
};

TLSRequest.prototype._onerror = function(err) {
  console.error(err.stack);
  process.exit();
};

TLSRequest.prototype._onclose = function() {
  console.log('closed');
}

module.exports = TLSRequest;