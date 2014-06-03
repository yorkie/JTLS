
var fs = require('fs');
var net = require('net');
var TLSHeader = require('tls-header');
var Handshake = require('tls-handshake').Handshake;
var HelloMessage = require('tls-handshake').HelloMessage;
var constants = require('tls-constants');
var debug = require('debug')('jtls');

function TLSRequest(port, host) {
  this._recordBuffer = null;
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
  this.socket.write(buf);
};

TLSRequest.prototype._ondata = function(chunk) {
  if (this._recordBuffer !== null) {
    chunk = Buffer.concat([this._recordBuffer, chunk]);
  }
  var offset = 0;
  var maxLength = chunk.length;
  while (offset < maxLength) {
    var record = {};
    record.type = constants.TLS.ContentTypes[chunk.readUInt8(offset++)];
    record.version = chunk.readUInt16BE(offset);
    offset += 2;
    record.length = chunk.readUInt16BE(offset);
    offset += 2;

    // if the expected length is bigger than the chunk size,
    if (offset + record.length > maxLength) {
      // fallback to the orignal offset
      offset -= 5;
      this._recordBuffer = chunk.slice(offset, maxLength);
      break;
    }
    record.buffer = chunk.slice(offset, offset + record.length);
    offset += record.length;
    this._emitRecord(record);
  }
};

TLSRequest.prototype._emitRecord = function(record) {
  switch (record.type) {
    case 'handshake':
      parseHandshake(record.buffer);
      break;
    case 'alert':
      parseAlert(record.buffer);
      break;
    default:
      debug('unknown type: %s', record.type);
      break;
  }

  function parseAlert(buffer) {
    var level = constants.alert.level[buffer[0]];
    var description = constants.alert.description[buffer[1]];
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

  function parseHandshake(buffer) {
    var type = constants.handshake.types[buffer[0]];
    var len = buffer.readUInt24BE(1);
    
    // FIXME(Yorkie): valid version
    // break version

    switch (type) {
      case 'server_hello':
        parseServerHello(buffer, 6); 
        break;
      case 'certificate':
        parseCertificate(buffer, 4, len);
        break;
      case 'server_key_exchange':
        parseServerKeyExchange(buffer);
        break;
      case 'server_hello_done':
        parseServerHelloDone(buffer);
        break;
    }
  }

  function parseServerHello(buffer, offset) {
    var serverHello = {}
    serverHello.type = 'serverHello';
    serverHello.date = buffer.readUInt32BE(offset) * 1000;
    offset += 4;
    serverHello.random = buffer.slice(offset, offset + 28).toString('hex');
    offset += 28;

    // sessionId
    var len = buffer.readUInt8(offset++);
    serverHello.sessionId = buffer.slice(offset, offset + len).toString('hex');
    offset += len;

    // cipher suite
    var cipherSuiteNumber = buffer.readUInt16BE(offset);
    offset += 2;
    serverHello.cipherSuite = constants.handshake.cipher_suites[cipherSuiteNumber];

    // compression
    serverHello.compression = buffer.readUInt8(offset++) == 1;
    console.log(serverHello);
  }

  function parseCertificate(buffer, offset, len) {
    var certificate = {
      type: 'certificate',
      raw: buffer.slice(offset, offset + len)
    };
    console.log(certificate);
  }

  function parseServerKeyExchange(buffer, offset) {
    console.log(buffer);
  }

  function parseServerHelloDone(buffer, offset) {
    console.log('serverHello done :)');
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