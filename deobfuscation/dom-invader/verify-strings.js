#!/usr/bin/env node
'use strict';
/*
 * Re-derives every mapping in decoded-strings.txt from the sample's own decoder
 * and fails if any line disagrees. Run it after editing that file:
 *
 *   node dom-invader/verify-strings.js
 */
const fs = require('fs');
const path = require('path');

// The alphabet embedded in the obfuscated script: standard base64, rotated so
// that lowercase letters occupy indices 0-25.
const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';

/** Faithful re-implementation of the decoder inside a4_0x5998. */
function decode(input) {
  let bytes = '', out = '';
  for (let bitPos = 0, acc, code, i = 0;
       (code = input.charAt(i++));
       ~code && ((acc = bitPos % 4 ? acc * 64 + code : code), bitPos++ % 4)
         ? (bytes += String.fromCharCode(255 & (acc >> ((-2 * bitPos) & 6))))
         : 0) {
    code = ALPHABET.indexOf(code);
  }
  for (let i = 0; i < bytes.length; i++) {
    out += '%' + ('00' + bytes.charCodeAt(i).toString(16)).slice(-2);
  }
  return decodeURIComponent(out);
}

const file = path.join(__dirname, 'decoded-strings.txt');
let checked = 0, bad = 0;
for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
  const m = line.match(/^(\S+)\s+->\s{2}(.*)$/);
  if (!m) continue;
  const [, encoded, claimed] = m;
  let actual;
  try { actual = decode(encoded); } catch (e) { actual = '<<decode error>>'; }
  checked++;
  if (actual !== claimed) {
    bad++;
    console.error(`MISMATCH ${encoded}\n  file:    ${JSON.stringify(claimed)}\n  decoder: ${JSON.stringify(actual)}`);
  }
}
console.log(`${checked} mapping(s) checked, ${bad} mismatch(es)`);
process.exit(bad ? 1 : 0);
