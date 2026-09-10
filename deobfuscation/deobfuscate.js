#!/usr/bin/env node
'use strict';
/*
 * deobfuscate.js — an AST-based deobfuscator for output of javascript-obfuscator
 * (a.k.a. obfuscator.io), the tool behind the DOM Invader script in ../samples/.
 *
 * It reverses, in order:
 *   1. string-array encoding      (rotated array + base64 decoder + alias wrappers)
 *   2. dispatcher/proxy objects    (`_0xabc123['key']` -> literal / inlined operator)
 *   3. literal normalisation       (!![] -> true, o['k'] -> o.k, constant folding)
 *   4. opaque predicates           (`if ('a' === 'b')` -> dead branch removed)
 *   5. control-flow flattening     (the `switch (order[i++])` shuffle)
 *   6. identifier renaming         (_0x4977b3 -> readable, scope-correct names)
 *
 * Usage:  node deobfuscate.js <input.js> [-o output.js] [--keep-names] [--no-rename]
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const parser = require('@babel/parser');
const traverseMod = require('@babel/traverse');
const generateMod = require('@babel/generator');
const t = require('@babel/types');

const traverse = traverseMod.default || traverseMod;
const generate = generateMod.default || generateMod;

// --------------------------------------------------------------------------
// small helpers
// --------------------------------------------------------------------------

const log = (...a) => process.env.QUIET ? undefined : console.error('[deobf]', ...a);

function parse(code) {
  return parser.parse(code, {
    sourceType: 'unambiguous',
    allowReturnOutsideFunction: true,
    errorRecovery: true,
    plugins: ['jsx'],
  });
}

function print(node) {
  return generate(node, { comments: true, jsescOption: { minimal: true } }).code;
}

/** Read a statically-known key out of a MemberExpression (o.k or o['k']). */
function memberKey(node) {
  if (!t.isMemberExpression(node)) return null;
  if (node.computed) {
    if (t.isStringLiteral(node.property)) return node.property.value;
    if (t.isNumericLiteral(node.property)) return String(node.property.value);
    return null;
  }
  return t.isIdentifier(node.property) ? node.property.name : null;
}

/** Evaluate a literal-ish node to a JS value; throws when not statically known. */
function literalValue(node) {
  if (t.isStringLiteral(node) || t.isNumericLiteral(node) || t.isBooleanLiteral(node)) return node.value;
  if (t.isNullLiteral(node)) return null;
  if (t.isUnaryExpression(node) && node.operator === '-') return -literalValue(node.argument);
  if (t.isUnaryExpression(node) && node.operator === '+') return +literalValue(node.argument);
  throw new Error('not a literal: ' + node.type);
}

function isLiteralNode(node) {
  try { literalValue(node); return true; } catch { return false; }
}

/** Turn a JS value back into an AST literal. */
function valueToNode(v) {
  if (typeof v === 'string') return t.stringLiteral(v);
  if (typeof v === 'boolean') return t.booleanLiteral(v);
  if (v === null) return t.nullLiteral();
  if (typeof v === 'number') {
    return v < 0 || Object.is(v, -0)
      ? t.unaryExpression('-', t.numericLiteral(Math.abs(v)))
      : t.numericLiteral(v);
  }
  if (typeof v === 'undefined') return t.identifier('undefined');
  throw new Error('cannot represent ' + typeof v);
}

// --------------------------------------------------------------------------
// PASS 1 — string-array decoding
// --------------------------------------------------------------------------
/*
 * The obfuscator emits three cooperating pieces at the top of the file:
 *
 *   function a4_0x2128() { const arr = ['...','...']; a4_0x2128 = () => arr; return arr; }
 *   function a4_0x5998(i, k) { ...indexes arr, base64-decodes, memoises... }
 *   (function (fn, target) { ...rotate arr until a checksum matches... })(a4_0x2128, 0xa6a0f);
 *
 * Rather than re-implement the decoder statically (the rotation makes that
 * fragile), we lift those three pieces into a sandboxed `vm` context and run
 * them.  Then every `a4_0x5998(0x123, 0x456)` call — and every local alias
 * wrapper that forwards to it — becomes a real string we can substitute.
 */

/** Locate the function whose body materialises the big string array. */
function findStringArrayFn(ast) {
  let best = null;
  traverse(ast, {
    FunctionDeclaration(p) {
      if (!p.node.id) return;
      let arrays = [];
      p.traverse({ ArrayExpression(a) {
        if (a.node.elements.length > 8 && a.node.elements.every(e => t.isStringLiteral(e))) {
          arrays.push(a.node.elements.length);
        }
      }});
      if (!arrays.length) return;
      const size = Math.max(...arrays);
      if (!best || size > best.size) best = { path: p, name: p.node.id.name, size };
    },
  });
  return best;
}

/** Locate the decoder: references the string-array fn and holds the base64 alphabet. */
function findDecoderFn(ast, stringArrayName) {
  let found = null;
  traverse(ast, {
    FunctionDeclaration(p) {
      if (!p.node.id || p.node.id.name === stringArrayName) return;
      let usesArray = false, hasAlphabet = false;
      p.traverse({
        Identifier(i) { if (i.node.name === stringArrayName) usesArray = true; },
        StringLiteral(s) {
          const v = s.node.value;
          if (v.length > 60 && /abcdefghijklmnopqrstuvwxyz/i.test(v)) hasAlphabet = true;
        },
      });
      if (usesArray && hasAlphabet && !found) found = { path: p, name: p.node.id.name };
    },
  });
  // Fallback: any top-level fn that references the array fn and takes 2 params.
  if (!found) {
    traverse(ast, {
      FunctionDeclaration(p) {
        if (found || !p.node.id || p.node.id.name === stringArrayName) return;
        if (p.node.params.length !== 2) return;
        let usesArray = false;
        p.traverse({ Identifier(i) { if (i.node.name === stringArrayName) usesArray = true; } });
        if (usesArray) found = { path: p, name: p.node.id.name };
      },
    });
  }
  return found;
}

/** Statements that rotate the array (the self-defending checksum IIFE). */
function findRotationStatements(ast, stringArrayName, decoderName) {
  const out = [];
  ast.program.body.forEach((stmt) => {
    if (!t.isExpressionStatement(stmt)) return;
    let mentionsArray = false;
    traverse(stmt, {
      noScope: true,
      Identifier(p) { if (p.node.name === stringArrayName) mentionsArray = true; },
    }, null, {}, null);
    if (mentionsArray) out.push(stmt);
  });
  return out;
}

/**
 * Build a sandbox exposing the real decoder plus every alias wrapper.
 * Returns { decode(aliasId, args) -> string, aliasBindings: Map }.
 */
function buildDecoderSandbox(ast) {
  const arrFn = findStringArrayFn(ast);
  if (!arrFn) return null;
  const decFn = findDecoderFn(ast, arrFn.name);
  if (!decFn) return null;

  log(`string array: ${arrFn.name} (${arrFn.size} entries), decoder: ${decFn.name}`);

  const rotation = findRotationStatements(ast, arrFn.name, decFn.name);

  const preludeParts = [print(arrFn.path.node), print(decFn.path.node)];
  for (const stmt of rotation) preludeParts.push(print(stmt));

  const sandbox = vm.createContext(Object.create(null));
  // Give the sandbox the globals the prelude legitimately needs.
  vm.runInContext(
    'var window=globalThis, self=globalThis, global=globalThis;',
    sandbox
  );

  try {
    vm.runInContext(preludeParts.join('\n'), sandbox, { timeout: 20000 });
  } catch (e) {
    log('WARNING: could not run decoder prelude:', e.message);
    return null;
  }

  return { sandbox, arrFn, decFn, rotation };
}

/**
 * Find every local wrapper that forwards to the decoder, e.g.
 *   function _0x395d81(a, b) { return a4_0x5998(b - 0x2e5, a); }
 * Aliases can chain, and the same name may be reused in sibling scopes, so we
 * key everything by Babel binding identity rather than by name.
 */
function collectAliases(ast, ctx) {
  const known = new Map();          // binding -> sandbox function name
  const rootName = ctx.decFn.name;
  let counter = 0;

  // Seed with the real decoder's own binding(s).
  traverse(ast, {
    Program(p) {
      const b = p.scope.getBinding(rootName);
      if (b) known.set(b, rootName);
    },
  });

  let changed = true;
  while (changed) {
    changed = false;
    traverse(ast, {
      Function(p) {
        const node = p.node;
        const id = t.isFunctionDeclaration(node) ? node.id
          : (t.isVariableDeclarator(p.parent) ? p.parent.id : null);
        if (!t.isIdentifier(id)) return;

        const body = node.body;
        if (!t.isBlockStatement(body) || body.body.length !== 1) return;
        const ret = body.body[0];
        if (!t.isReturnStatement(ret) || !t.isCallExpression(ret.argument)) return;
        const callee = ret.argument.callee;
        if (!t.isIdentifier(callee)) return;

        const calleeBinding = p.scope.getBinding(callee.name);
        if (!calleeBinding || !known.has(calleeBinding)) return;

        const declScope = t.isFunctionDeclaration(node) ? p.scope.parent : p.scope.parent;
        const binding = declScope && declScope.getBinding(id.name);
        if (!binding || known.has(binding)) return;

        const sandboxName = `__alias_${counter++}`;
        // Re-emit the wrapper with its callee pointing at the resolved sandbox name.
        const clone = t.cloneNode(node, true);
        traverse(t.file(t.program([t.expressionStatement(t.toExpression(t.cloneNode(clone, true)))])), {
          noScope: true,
        });
        const src = print(clone).replace(/^function\s*[A-Za-z0-9_$]*/, 'function');
        const rewritten = src.replace(
          new RegExp('\\b' + callee.name.replace(/[$]/g, '\\$') + '\\b', 'g'),
          known.get(calleeBinding)
        );
        try {
          vm.runInContext(`var ${sandboxName} = ${rewritten};`, ctx.sandbox, { timeout: 5000 });
          known.set(binding, sandboxName);
          changed = true;
        } catch (e) {
          log('alias compile failed for', id.name, '-', e.message);
        }
      },
    });
  }
  log(`resolved ${known.size} decoder alias binding(s)`);
  return known;
}

/** Replace every decoder/alias call that has literal arguments with its string. */
function inlineDecoderCalls(ast, ctx, aliasBindings) {
  let replaced = 0, failed = 0;
  traverse(ast, {
    CallExpression(p) {
      const callee = p.node.callee;
      if (!t.isIdentifier(callee)) return;
      const binding = p.scope.getBinding(callee.name);
      if (!binding || !aliasBindings.has(binding)) return;
      if (!p.node.arguments.every(isLiteralNode)) return;

      const fnName = aliasBindings.get(binding);
      const args = p.node.arguments.map(literalValue);
      try {
        ctx.sandbox.__args = args;
        const out = vm.runInContext(`${fnName}.apply(null, __args)`, ctx.sandbox, { timeout: 5000 });
        if (typeof out !== 'string') { failed++; return; }
        p.replaceWith(t.stringLiteral(out));
        replaced++;
      } catch (e) {
        failed++;
      }
    },
  });
  log(`decoded ${replaced} string reference(s)` + (failed ? `, ${failed} failed` : ''));
  return replaced;
}

/** Delete the now-dead string array, decoder, rotation IIFE and alias wrappers. */
function removeDecoderScaffolding(ast, ctx, aliasBindings) {
  const doomedNames = new Set([ctx.arrFn.name, ctx.decFn.name]);
  for (const stmt of ctx.rotation) {
    const idx = ast.program.body.indexOf(stmt);
    if (idx !== -1) ast.program.body.splice(idx, 1);
  }
  traverse(ast, {
    Function(p) {
      const node = p.node;
      const id = t.isFunctionDeclaration(node) ? node.id
        : (t.isVariableDeclarator(p.parent) ? p.parent.id : null);
      if (!t.isIdentifier(id)) return;
      const scope = p.scope.parent || p.scope;
      const binding = scope.getBinding(id.name);
      const isAlias = binding && aliasBindings.has(binding);
      if (!isAlias && !doomedNames.has(id.name)) return;
      if (binding && binding.referencePaths.some(rp => !rp.removed && rp.node !== id)) {
        // still referenced somewhere we could not decode — keep it
        const live = binding.referencePaths.filter(rp => rp.find(x => x.node === ast) );
        if (live.length) return;
      }
      if (t.isVariableDeclarator(p.parent)) p.parentPath.remove();
      else p.remove();
    },
  });
}

// --------------------------------------------------------------------------
// PASS 2 — dispatcher / proxy object inlining
// --------------------------------------------------------------------------
/*
 * The obfuscator hoists constants and tiny operator wrappers into a lookup
 * object at the top of each function:
 *
 *   const _0x4977b3 = {
 *     'omuUi': function (a, b) { return a === b; },
 *     'PdZQG': 'string',
 *     'fPTPC': function (f, a, b, c, d) { return f(a, b, c, d); },
 *   };
 *   ... if (_0x4977b3['omuUi'](typeof x, _0x4977b3['PdZQG'])) ...
 *
 * We inline the constants and unwrap the operator/call proxies, which is what
 * makes the opaque-predicate pass below able to see through the conditions.
 */

/** Substitute call arguments into a one-line `return <expr>` proxy body. */
function inlineProxyCall(fnNode, argNodes) {
  if (!t.isBlockStatement(fnNode.body) || fnNode.body.body.length !== 1) return null;
  const ret = fnNode.body.body[0];
  if (!t.isReturnStatement(ret) || !ret.argument) return null;
  const params = fnNode.params;
  if (!params.every(p => t.isIdentifier(p))) return null;
  if (argNodes.length !== params.length) return null;

  const names = params.map(p => p.name);
  const uses = Object.fromEntries(names.map(n => [n, 0]));
  (function count(node) {
    if (!node || typeof node.type !== 'string') return;
    if (t.isIdentifier(node) && Object.prototype.hasOwnProperty.call(uses, node.name)) uses[node.name]++;
    for (const key of t.VISITOR_KEYS[node.type] || []) {
      const child = node[key];
      if (Array.isArray(child)) child.forEach(count); else count(child);
    }
  })(ret.argument);

  const simple = (n) => t.isIdentifier(n) || isLiteralNode(n) ||
    (t.isMemberExpression(n) && !n.computed && t.isIdentifier(n.object));
  for (let i = 0; i < names.length; i++) {
    if (uses[names[i]] > 1) return null;                 // would duplicate side effects
    if (uses[names[i]] === 0 && !simple(argNodes[i])) return null; // would drop them
  }

  const map = Object.fromEntries(names.map((n, i) => [n, argNodes[i]]));
  const out = t.cloneNode(ret.argument, true);
  (function subst(node, parent, key, index) {
    if (!node || typeof node.type !== 'string') return;
    if (t.isIdentifier(node) && Object.prototype.hasOwnProperty.call(map, node.name)) {
      const repl = t.cloneNode(map[node.name], true);
      if (index === undefined) parent[key] = repl; else parent[key][index] = repl;
      return;
    }
    for (const k of t.VISITOR_KEYS[node.type] || []) {
      const child = node[k];
      if (Array.isArray(child)) child.forEach((c, i) => subst(c, node, k, i));
      else subst(child, node, k);
    }
  })(out, { root: out }, 'root');
  return out;
}

function inlineDispatcherObjects(ast) {
  let total = 0;
  traverse(ast, {
    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (!t.isIdentifier(id) || !t.isObjectExpression(init)) return;
      if (init.properties.length === 0) return;

      const table = new Map();
      for (const prop of init.properties) {
        if (!t.isObjectProperty(prop) || prop.computed) return;
        const key = t.isStringLiteral(prop.key) ? prop.key.value
          : (t.isIdentifier(prop.key) ? prop.key.name : null);
        if (key === null) return;
        const v = prop.value;
        if (isLiteralNode(v) || t.isFunctionExpression(v) || t.isArrowFunctionExpression(v)) {
          table.set(key, v);
        } else if (key === '__proto__' && t.isNullLiteral(v)) {
          table.set(key, v);
        } else {
          return; // not a pure constant table — leave it alone
        }
      }

      const binding = p.scope.getBinding(id.name);
      if (!binding || !binding.constant) return;

      // Every reference must be a plain `obj.key` / `obj['key']` read.
      const refs = binding.referencePaths;
      if (!refs.length) return;
      for (const ref of refs) {
        const mp = ref.parentPath;
        if (!mp || !t.isMemberExpression(mp.node) || mp.node.object !== ref.node) return;
        const key = memberKey(mp.node);
        if (key === null || !table.has(key)) return;
        if (mp.parentPath && t.isAssignmentExpression(mp.parentPath.node) &&
            mp.parentPath.node.left === mp.node) return;
      }

      // Replacing a proxy call can delete sibling references, so re-scan the
      // declaring scope after every single substitution instead of walking a
      // (rapidly stale) referencePaths snapshot.
      let replacedHere = 0;
      const scopePath = binding.scope.path;
      for (let guard = 0; guard < 100000; guard++) {
        let didOne = false;
        scopePath.traverse({
          MemberExpression(mp) {
            if (didOne || mp.removed || !mp.node) return;
            if (!t.isIdentifier(mp.node.object) || mp.node.object.name !== id.name) return;
            if (mp.scope.getBinding(id.name) !== binding) return;
            const key = memberKey(mp.node);
            if (key === null || !table.has(key)) return;
            const value = table.get(key);
            const gp = mp.parentPath;
            if ((t.isFunctionExpression(value) || t.isArrowFunctionExpression(value)) &&
                gp && !gp.removed && t.isCallExpression(gp.node) && gp.node.callee === mp.node) {
              const inlined = inlineProxyCall(value, gp.node.arguments);
              if (inlined) { gp.replaceWith(inlined); didOne = true; replacedHere++; return; }
            }
            mp.replaceWith(t.cloneNode(value, true));
            didOne = true; replacedHere++;
          },
        });
        if (!didOne) break;
      }

      if (replacedHere) { total += replacedHere; if (!p.removed) p.remove(); }
    },
  });
  if (total) log(`inlined ${total} dispatcher-object reference(s)`);
  return total;
}

// --------------------------------------------------------------------------
// PASS 3 — literal normalisation & constant folding
// --------------------------------------------------------------------------

function normaliseLiterals(ast) {
  let n = 0;
  traverse(ast, {
    // strip `extra` so hex numbers print as decimal and quotes stay uniform
    NumericLiteral(p) { if (p.node.extra) delete p.node.extra; },
    StringLiteral(p) { if (p.node.extra) delete p.node.extra; },

    // !![] -> true, ![] -> false, !!{} -> true, typeof 'x' -> 'string', void 0 -> undefined
    UnaryExpression(p) {
      if (p.node.operator === 'void' && isLiteralNode(p.node.argument)) {
        p.replaceWith(t.identifier('undefined')); n++; return;
      }
      if (p.node.operator === 'typeof') {
        const a = p.node.argument;
        if (isLiteralNode(a)) { p.replaceWith(t.stringLiteral(typeof literalValue(a))); n++; return; }
        if (t.isFunctionExpression(a) || t.isArrowFunctionExpression(a)) {
          p.replaceWith(t.stringLiteral('function')); n++; return;
        }
        if (t.isArrayExpression(a) || t.isObjectExpression(a)) {
          p.replaceWith(t.stringLiteral('object')); n++; return;
        }
        return;
      }
      if (p.node.operator !== '!') return;
      const inner = p.node.argument;
      if (t.isArrayExpression(inner) && inner.elements.length === 0) { p.replaceWith(t.booleanLiteral(false)); n++; return; }
      if (t.isObjectExpression(inner) && inner.properties.length === 0) { p.replaceWith(t.booleanLiteral(false)); n++; return; }
      if (t.isUnaryExpression(inner) && inner.operator === '!') {
        const deep = inner.argument;
        if ((t.isArrayExpression(deep) && !deep.elements.length) ||
            (t.isObjectExpression(deep) && !deep.properties.length)) {
          p.replaceWith(t.booleanLiteral(true)); n++; return;
        }
      }
      if (t.isBooleanLiteral(inner)) { p.replaceWith(t.booleanLiteral(!inner.value)); n++; }
    },

    // o['prop'] -> o.prop when the key is a valid identifier
    MemberExpression(p) {
      if (!p.node.computed || !t.isStringLiteral(p.node.property)) return;
      const v = p.node.property.value;
      if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(v)) return;
      p.node.computed = false;
      p.node.property = t.identifier(v);
      n++;
    },

    // 'a' + 'b' -> 'ab';  1 + 2 -> 3;  'a' === 'a' -> true
    BinaryExpression: {
      exit(p) {
        const { left, right, operator } = p.node;
        if (!isLiteralNode(left) || !isLiteralNode(right)) return;
        let out;
        try {
          const a = literalValue(left), b = literalValue(right);
          switch (operator) {
            case '+': out = a + b; break;
            case '-': out = a - b; break;
            case '*': out = a * b; break;
            case '/': out = a / b; break;
            case '%': out = a % b; break;
            case '===': out = a === b; break;
            case '!==': out = a !== b; break;
            case '==': out = a == b; break;
            case '!=': out = a != b; break;
            case '<': out = a < b; break;
            case '>': out = a > b; break;
            case '<=': out = a <= b; break;
            case '>=': out = a >= b; break;
            case '|': out = a | b; break;
            case '&': out = a & b; break;
            case '^': out = a ^ b; break;
            default: return;
          }
        } catch { return; }
        if (typeof out === 'number' && !Number.isFinite(out)) return;
        p.replaceWith(valueToNode(out));
        n++;
      },
    },
  });
  if (n) log(`normalised ${n} literal expression(s)`);
  return n;
}

// --------------------------------------------------------------------------
// PASS 4 — opaque predicates / dead branches
// --------------------------------------------------------------------------

function truthiness(node) {
  if (t.isBooleanLiteral(node)) return node.value;
  if (t.isStringLiteral(node)) return node.value.length > 0;
  if (t.isNumericLiteral(node)) return node.value !== 0;
  if (t.isNullLiteral(node)) return false;
  if (t.isArrayExpression(node) || t.isObjectExpression(node) || t.isFunctionExpression(node)) return true;
  if (t.isUnaryExpression(node) && node.operator === '!') {
    const inner = truthiness(node.argument);
    return inner === null ? null : !inner;
  }
  return null;
}

function removeDeadBranches(ast) {
  let n = 0;
  traverse(ast, {
    IfStatement(p) {
      const v = truthiness(p.node.test);
      if (v === null) return;
      const keep = v ? p.node.consequent : p.node.alternate;
      if (!keep) { p.remove(); n++; return; }
      p.replaceWithMultiple(t.isBlockStatement(keep) ? keep.body : [keep]);
      n++;
    },
    ConditionalExpression(p) {
      const v = truthiness(p.node.test);
      if (v === null) return;
      p.replaceWith(v ? p.node.consequent : p.node.alternate);
      n++;
    },
    LogicalExpression(p) {
      const v = truthiness(p.node.left);
      if (v === null) return;
      if (p.node.operator === '&&') { p.replaceWith(v ? p.node.right : p.node.left); n++; }
      else if (p.node.operator === '||') { p.replaceWith(v ? p.node.left : p.node.right); n++; }
    },
    // strip statements that can never be reached
    BlockStatement(p) {
      const body = p.node.body;
      const stop = body.findIndex(s => t.isReturnStatement(s) || t.isContinueStatement(s) ||
                                       t.isBreakStatement(s) || t.isThrowStatement(s));
      if (stop !== -1 && stop < body.length - 1) {
        const tail = body.slice(stop + 1);
        // keep hoisted declarations, drop the rest
        const keep = tail.filter(s => t.isFunctionDeclaration(s) ||
          (t.isVariableDeclaration(s) && s.kind === 'var'));
        p.node.body = body.slice(0, stop + 1).concat(keep);
        n++;
      }
    },
  });
  if (n) log(`removed ${n} dead branch(es)/statement(s)`);
  return n;
}

// --------------------------------------------------------------------------
// PASS 5 — control-flow unflattening (the switch shuffle)
// --------------------------------------------------------------------------
/*
 *   const order = '3|1|0|2'.split('|');
 *   let i = 0;
 *   while (true) { switch (order[i++]) { case '0': A; continue; case '1': B; continue; } break; }
 *
 * becomes the straight-line sequence A..D re-ordered per `order`.
 */
function unflattenControlFlow(ast) {
  let n = 0;
  traverse(ast, {
    WhileStatement(p) {
      if (truthiness(p.node.test) !== true) return;
      const body = t.isBlockStatement(p.node.body) ? p.node.body.body : [p.node.body];
      const sw = body.find(s => t.isSwitchStatement(s));
      if (!sw) return;
      if (!body.every(s => s === sw || t.isBreakStatement(s))) return;

      // discriminant must be `order[i++]`
      const d = sw.discriminant;
      if (!t.isMemberExpression(d) || !d.computed) return;
      if (!t.isIdentifier(d.object)) return;
      if (!t.isUpdateExpression(d.property) || d.property.operator !== '++') return;
      if (!t.isIdentifier(d.property.argument)) return;
      const orderName = d.object.name;
      const idxName = d.property.argument.name;

      // find `const order = '...'.split('|')` in an enclosing scope
      const orderBinding = p.scope.getBinding(orderName);
      if (!orderBinding || !t.isVariableDeclarator(orderBinding.path.node)) return;
      const init = orderBinding.path.node.init;
      if (!t.isCallExpression(init) || memberKey(init.callee) !== 'split') return;
      if (!t.isStringLiteral(init.callee.object)) return;
      if (init.arguments.length !== 1 || !t.isStringLiteral(init.arguments[0])) return;
      const order = init.callee.object.value.split(init.arguments[0].value);

      // map case label -> statements
      const cases = new Map();
      for (const c of sw.cases) {
        if (!c.test || !t.isStringLiteral(c.test)) return;
        const stmts = c.consequent.filter(s => !t.isContinueStatement(s));
        cases.set(c.test.value, stmts);
      }
      if (!order.every(k => cases.has(k))) return;

      const flat = [];
      for (const key of order) flat.push(...cases.get(key).map(s => t.cloneNode(s, true)));

      p.replaceWithMultiple(flat);

      // drop the now-unused order/index declarations
      for (const name of [orderName, idxName]) {
        const b = p.scope.getBinding(name);
        if (b && b.referencePaths.every(r => r.removed || !r.node)) {
          if (t.isVariableDeclarator(b.path.node)) { try { b.path.remove(); } catch {} }
        }
      }
      n++;
    },
  });
  if (n) log(`unflattened ${n} control-flow switch block(s)`);
  return n;
}

// --------------------------------------------------------------------------
// PASS 5b — dead variable / dead function elimination
// --------------------------------------------------------------------------

const SAFE_METHODS = new Set(['split', 'join', 'slice', 'concat', 'trim',
  'toUpperCase', 'toLowerCase', 'charAt', 'charCodeAt', 'indexOf', 'substring']);

/** Conservative purity check — only used to decide if a dead binding is safe to drop. */
function isPure(node) {
  if (!node) return true;
  if (isLiteralNode(node) || t.isIdentifier(node)) return true;
  if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) return true;
  if (t.isArrayExpression(node)) return node.elements.every(e => e === null || isPure(e));
  if (t.isObjectExpression(node)) {
    return node.properties.every(pr => t.isObjectProperty(pr) && !pr.computed && isPure(pr.value));
  }
  if (t.isUnaryExpression(node)) return node.operator !== 'delete' && isPure(node.argument);
  if (t.isBinaryExpression(node)) return isPure(node.left) && isPure(node.right);
  if (t.isMemberExpression(node)) return isPure(node.object) && (!node.computed || isPure(node.property));
  if (t.isCallExpression(node)) {
    return t.isMemberExpression(node.callee) &&
      SAFE_METHODS.has(memberKey(node.callee)) &&
      isPure(node.callee.object) && node.arguments.every(isPure);
  }
  return false;
}

function eliminateDeadCode(ast) {
  let n = 0;
  traverse(ast, {
    Scopable(p) {
      p.scope.crawl();
      for (const name of Object.keys(p.scope.bindings)) {
        const b = p.scope.bindings[name];
        if (b.referenced || !b.constant) continue;
        const node = b.path.node;
        if (t.isVariableDeclarator(node)) {
          if (!isPure(node.init)) continue;
          b.path.remove(); n++;
        } else if (t.isFunctionDeclaration(node) && HEXNAME.test(name)) {
          b.path.remove(); n++;
        }
      }
    },
  });
  if (n) log(`removed ${n} dead binding(s)`);
  return n;
}

// --------------------------------------------------------------------------
// PASS 6 — identifier renaming
// --------------------------------------------------------------------------

const HEXNAME = /^(?:_0x[0-9a-fA-F]+|[A-Za-z]\w*_0x[0-9a-fA-F]+)$/;

function renameIdentifiers(ast) {
  let counters = { fn: 0, param: 0, v: 0 };
  const seen = new Set();
  traverse(ast, {
    Scopable(p) {
      for (const name of Object.keys(p.scope.bindings)) {
        if (!HEXNAME.test(name) || seen.has(name)) continue;
        const binding = p.scope.bindings[name];
        let base;
        if (binding.kind === 'param') base = 'arg' + (++counters.param);
        else if (t.isFunction(binding.path.node) ||
                 (t.isVariableDeclarator(binding.path.node) && t.isFunction(binding.path.node.init))) {
          base = 'fn' + (++counters.fn);
        } else base = 'v' + (++counters.v);
        let fresh = base, i = 2;
        while (p.scope.hasBinding(fresh) || seen.has(fresh)) fresh = base + '_' + i++;
        seen.add(fresh);
        p.scope.rename(name, fresh);
      }
    },
  });
  log('renamed obfuscated identifiers');
}

// --------------------------------------------------------------------------
// driver
// --------------------------------------------------------------------------

function deobfuscate(code, opts = {}) {
  let ast = parse(code);

  const ctx = buildDecoderSandbox(ast);
  if (ctx) {
    const aliases = collectAliases(ast, ctx);
    inlineDecoderCalls(ast, ctx, aliases);
    removeDecoderScaffolding(ast, ctx, aliases);
  } else {
    log('no string-array layer detected — continuing with the other passes');
  }

  // The remaining transforms feed each other, so iterate to a fixed point.
  for (let round = 0; round < 12; round++) {
    const changes =
      inlineDispatcherObjects(ast) +
      normaliseLiterals(ast) +
      removeDeadBranches(ast) +
      unflattenControlFlow(ast) +
      eliminateDeadCode(ast);
    log(`round ${round + 1}: ${changes} change(s)`);
    if (!changes) break;
    // re-parse periodically so scope info stays accurate after heavy surgery
    ast = parse(print(ast));
  }

  if (opts.rename !== false) renameIdentifiers(ast);

  return generate(ast, {
    comments: true,
    retainLines: false,
    compact: false,
    concise: false,
    jsescOption: { minimal: true, quotes: 'single', wrap: true },
  }).code;
}

module.exports = { deobfuscate, parse, print };

if (require.main === module) {
  const argv = process.argv.slice(2);
  const input = argv.find(a => !a.startsWith('-'));
  if (!input) {
    console.error('usage: node deobfuscate.js <input.js> [-o output.js] [--no-rename]');
    process.exit(1);
  }
  const oIdx = argv.indexOf('-o');
  const output = oIdx !== -1 ? argv[oIdx + 1] : null;
  const src = fs.readFileSync(input, 'utf8');
  const out = deobfuscate(src, { rename: !argv.includes('--no-rename') });
  if (output) { fs.writeFileSync(output, out + '\n'); log('wrote ' + output); }
  else process.stdout.write(out + '\n');
}
