#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');
const { Certificate } = require('@fidm/x509');

const args = process.argv.slice(2);
for (const arg of args) {
  const cert = Certificate.fromPEM(fs.readFileSync(arg, 'utf8'));
  console.log(getHash(cert.raw));
}

function getHash(content, inputEncoding = 'utf8', outputEncoding = 'hex') {
  const shasum = crypto.createHash('sha256');
  shasum.update(content, inputEncoding);
  const res = shasum.digest(outputEncoding);
  return res;
};
