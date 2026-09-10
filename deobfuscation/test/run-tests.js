'use strict';
/* Round-trip test: obfuscated fixture -> deobfuscator -> clean source.
 * Asserts the result is (a) free of obfuscation artefacts and
 * (b) semantically identical to the obfuscated original. */
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');
const { deobfuscate } = require('../deobfuscate.js');

let failures = 0;
const check = (name, cond, detail) => {
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n        ' + detail}`);
  if (!cond) failures++;
};

execFileSync(process.execPath, [path.join(__dirname, 'make-fixture.js')], { stdio: 'ignore' });

const fixturePath = path.join(__dirname, 'fixture-obfuscated.js');
const obfuscated = fs.readFileSync(fixturePath, 'utf8');

// Behaviour of the obfuscated original.
delete require.cache[require.resolve(fixturePath)];
const expected = require(fixturePath)();

process.env.QUIET = '1';
const clean = deobfuscate(obfuscated);

const tmp = path.join(os.tmpdir(), `deobf-clean-${process.pid}.js`);
fs.writeFileSync(tmp, clean);
const actual = require(tmp)();
fs.unlinkSync(tmp);

check('behaviour preserved', actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
check('string array decoded', clean.includes('hello world') && clean.includes('toUpperCase'));
check('decoder scaffolding removed', !/fx_0x1000|fx_0x2000|decodeURIComponent/.test(clean));
check('dispatcher object inlined', !/_0x4977b3/.test(clean));
check('opaque predicate resolved', !clean.includes('unreachable'));
check('control flow unflattened', !clean.includes("split('|')") && !clean.includes('switch'));
check('hex identifiers renamed', !/_0x[0-9a-f]+/i.test(clean));
check('output parses', (() => { try { new Function(clean.replace(/module\.exports.*/, '')); return true; } catch { return false; } })());

console.log(`\n${failures ? failures + ' test(s) FAILED' : 'all tests passed'}`);
process.exit(failures ? 1 : 0);
