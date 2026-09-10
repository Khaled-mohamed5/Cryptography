'use strict';
/*
 * Builds test/fixture-obfuscated.js using the *same* scheme as the DOM Invader
 * sample: rotated string array + custom-alphabet base64 decoder + alias
 * wrapper + dispatcher object + opaque predicates + control-flow flattening.
 */
const fs = require('fs');
const path = require('path');

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';

/** Inverse of the decoder embedded in the obfuscated file. */
function encode(str) {
  const bytes = Buffer.from(str, 'utf8');
  let out = '', bits = 0, acc = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 6) { bits -= 6; out += ALPHABET[(acc >> bits) & 63]; }
  }
  if (bits > 0) out += ALPHABET[(acc << (6 - bits)) & 63];
  return out;
}

// Strings the fixture program needs, in final (post-rotation) order.
const STRINGS = [
  'log',            // 0
  'hello world',    // 1
  'string',         // 2
  'push',           // 3
  'length',         // 4
  'join',           // 5
  '-',              // 6
  'toUpperCase',    // 7
  '17',             // 8  (numeric, used by the checksum)
  '9',              // 9
  'flattened',      // 10
];

const INDEX_OFFSET = 0x136;   // decoder subtracts this, exactly like the sample
const ROTATION = 4;           // how far the self-defending IIFE must rotate

// Pre-rotate backwards so the IIFE's `push(shift())` restores the real order.
const rotated = STRINGS.slice();
for (let i = 0; i < ROTATION; i++) rotated.unshift(rotated.pop());

const encoded = STRINGS.map(encode);
const encodedRotated = rotated.map(encode);

// checksum: parseInt('17') * 2 + parseInt('9') === 43
const IDX_17 = STRINGS.indexOf('17') + INDEX_OFFSET;
const IDX_9  = STRINGS.indexOf('9')  + INDEX_OFFSET;
const TARGET = 17 * 2 + 9;

const src = `
function fx_0x1000() {
    const _0x9a8b7c = ${JSON.stringify(encodedRotated)};
    fx_0x1000 = function () { return _0x9a8b7c; };
    return fx_0x1000();
}
function fx_0x2000(_0x17288e, _0x41b18e) {
    const _0x21280b = fx_0x1000();
    return fx_0x2000 = function (_0x599881, _0x56a372) {
        _0x599881 = _0x599881 - 0x${INDEX_OFFSET.toString(16)};
        let _0x354855 = _0x21280b[_0x599881];
        if (fx_0x2000['NGnqMB'] === undefined) {
            var _0x7e4aeb = function (_0x4f033d) {
                const _0x37b755 = '${ALPHABET}';
                let _0x25fe01 = '', _0x42f3f3 = '';
                for (let _0x590f78 = 0x0, _0x199802, _0x288c76, _0x324b09 = 0x0; _0x288c76 = _0x4f033d['charAt'](_0x324b09++); ~_0x288c76 && (_0x199802 = _0x590f78 % 0x4 ? _0x199802 * 0x40 + _0x288c76 : _0x288c76, _0x590f78++ % 0x4) ? _0x25fe01 += String['fromCharCode'](0xff & _0x199802 >> (-0x2 * _0x590f78 & 0x6)) : 0x0) {
                    _0x288c76 = _0x37b755['indexOf'](_0x288c76);
                }
                for (let _0x2d2658 = 0x0, _0x59ce8c = _0x25fe01['length']; _0x2d2658 < _0x59ce8c; _0x2d2658++) {
                    _0x42f3f3 += '%' + ('00' + _0x25fe01['charCodeAt'](_0x2d2658)['toString'](0x10))['slice'](-0x2);
                }
                return decodeURIComponent(_0x42f3f3);
            };
            fx_0x2000['woatov'] = _0x7e4aeb, _0x17288e = arguments, fx_0x2000['NGnqMB'] = !![];
        }
        const _0x1a2729 = _0x21280b[0x0], _0x4f525d = _0x599881 + _0x1a2729, _0x4291f5 = _0x17288e[_0x4f525d];
        return !_0x4291f5 ? (_0x354855 = fx_0x2000['woatov'](_0x354855), _0x17288e[_0x4f525d] = _0x354855) : _0x354855 = _0x4291f5, _0x354855;
    }, fx_0x2000(_0x17288e, _0x41b18e);
}
(function (_0x59685f, _0xcf07fb) {
    function _0x13351f(_0xe9fac1, _0x1ff88b) { return fx_0x2000(_0x1ff88b - -0x10, _0xe9fac1); }
    const _0x28e21b = _0x59685f();
    while (!![]) {
        try {
            const _0x5bf354 = parseInt(_0x13351f(0x0, 0x${(IDX_17 - 0x10).toString(16)})) * 0x2 + parseInt(_0x13351f(0x0, 0x${(IDX_9 - 0x10).toString(16)}));
            if (_0x5bf354 === _0xcf07fb) break;
            else _0x28e21b['push'](_0x28e21b['shift']());
        } catch (_0x403a1f) { _0x28e21b['push'](_0x28e21b['shift']()); }
    }
}(fx_0x1000, 0x${TARGET.toString(16)}));

function fx_0x3000() {
    function _0x395d81(_0x1cc764, _0x455c1c) { return fx_0x2000(_0x455c1c - 0x2e5, _0x1cc764); }
    const _0x4977b3 = {
        'omuUi': function (_0x50c308, _0x3875cc) { return _0x50c308 === _0x3875cc; },
        'gMGrE': function (_0x1278d8, _0x50e5c9) { return _0x1278d8 + _0x50e5c9; },
        'fPTPC': function (_0x29d084, _0x2eb1de) { return _0x29d084(_0x2eb1de); },
        'PdZQG': _0x395d81(0xaaa, 0x${(2 + INDEX_OFFSET + 0x2e5).toString(16)}),
        'XDkrY': _0x395d81(0xbbb, 0x${(1 + INDEX_OFFSET + 0x2e5).toString(16)}),
        'sepch': _0x395d81(0xccc, 0x${(6 + INDEX_OFFSET + 0x2e5).toString(16)})
    };
    const _0x2ee63c = [];
    if (_0x4977b3['omuUi'](typeof _0x4977b3['XDkrY'], _0x4977b3['PdZQG'])) {
        const _0xf186ab = '2|0|3|1'['split']('|');
        let _0x321eff = 0x0;
        while (!![]) {
            switch (_0xf186ab[_0x321eff++]) {
            case '0':
                _0x2ee63c[_0x395d81(0x111, 0x${(3 + INDEX_OFFSET + 0x2e5).toString(16)})]('second');
                continue;
            case '1':
                return _0x2ee63c[_0x395d81(0x222, 0x${(5 + INDEX_OFFSET + 0x2e5).toString(16)})](_0x4977b3['sepch']);
            case '2':
                _0x2ee63c['push'](_0x4977b3['fPTPC'](function (_0x1) { return _0x1[_0x395d81(0x333, 0x${(7 + INDEX_OFFSET + 0x2e5).toString(16)})](); }, _0x4977b3['XDkrY']));
                continue;
            case '3':
                _0x2ee63c['push'](_0x4977b3['gMGrE'](_0x395d81(0x444, 0x${(10 + INDEX_OFFSET + 0x2e5).toString(16)}), '!'));
                continue;
            }
            break;
        }
    } else {
        return 'unreachable';
    }
}
module.exports = fx_0x3000;
`.trim();

fs.writeFileSync(path.join(__dirname, 'fixture-obfuscated.js'), src + '\n');
console.log('wrote test/fixture-obfuscated.js');
