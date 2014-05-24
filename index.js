
var net = require('net');
var TLSHeader = require('tls-header');
var Handshake = require('tls-handshake').Handshake;
var HelloMessage = require('tls-handshake').HelloMessage;

function TLSRequest(port, host) {
  this.socket = net.connect(port, host, this._onsocketConnected.bind(this));
  this.socket.on('data', this._ondata.bind(this));
  this.socket.on('error', this._onerror.bind(this));
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
  this.socket.write(buf);
};

TLSRequest.prototype._ondata = function(chunk) {
  console.log('haha');
  console.log(chunk);
};

TLSRequest.prototype._onerror = function(err) {
  console.error(err.stack);
  process.exit();
};

module.exports = TLSRequest;