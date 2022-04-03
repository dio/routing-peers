#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');
const { Certificate } = require('@fidm/x509');

const args = process.argv.slice(2);
for (const arg of args) {
  const cert = Certificate.fromPEM(fs.readFileSync(arg, 'utf8'));
  console.log(crypto.createHash('sha256').update(cert.raw, 'utf8').digest('hex'));
}
