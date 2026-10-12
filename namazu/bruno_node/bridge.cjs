'use strict';
// Only syntax parsing/serialization. No Bruno runner, evaluation, interpolation,
// script imports, environment access or file references from uploaded content.
const parser = require('./parser.cjs');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', data => {
  input += data;
  if (Buffer.byteLength(input) > 12 * 1024 * 1024) process.exit(2);
});
process.stdin.on('end', () => {
  try {
    const {action, items} = JSON.parse(input);
    if (!['parse', 'serialize'].includes(action) || !Array.isArray(items) || items.length > 500) throw Error();
    const result = items.map(item => {
      const allowed = action === 'parse' ? ['request','collection','environment'] : ['requestText','environmentText'];
      if (!allowed.includes(item.kind)) throw Error();
      return parser[item.kind](item.value);
    });
    process.stdout.write(JSON.stringify({result}));
  } catch {
    // Parser exceptions can include original credential-bearing source lines.
    process.stdout.write(JSON.stringify({error:'Invalid or unsupported Bruno syntax. Check the selected .bru files with @usebruno/lang 0.40.0.'}));
    process.exitCode = 1;
  }
});
