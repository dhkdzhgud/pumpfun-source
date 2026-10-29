import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { parseExpression } from '@babel/parser';
import { openCorpus, findNodes } from '../scripts/original-contracts/source.mjs';
import { createSchemaExtractor } from '../scripts/original-contracts/schema.mjs';
import { validateDeclared } from '../scripts/original-contracts/validate.mjs';

// Use the real captured declaration context and authenticated primitive ASTs.
// Only the literal argument below is synthetic; no captured code is executed.
const corpus = await openCorpus(fileURLToPath(new URL('..', import.meta.url)));
const extractor = createSchemaExtractor(corpus);
const { factory } = await extractor.declaration(421504, 'calloutDto');
const primitiveCall = findNodes(factory.node, node => node.type === 'CallExpression' &&
  node.callee.type === 'MemberExpression' && ['string', 'number', 'boolean'].includes(node.callee.property.name) &&
  node.callee.object.type === 'MemberExpression' && node.callee.object.property.name === 'z')[0];
assert.ok(primitiveCall, 'retained DTO has an authenticated Zod constructor');

async function compileLiteral(argument) {
  const expression = structuredClone(primitiveCall);
  expression.callee.property.name = 'literal';
  expression.arguments = [parseExpression(argument)];
  return extractor.compile(expression, factory);
}

for (const argument of ['1e999', '-1e999', '[1e999]', '[1, -1e999]']) {
  test(`non-finite literal ${argument} cannot silently become a null JSON constraint`, async () => {
    const schema = await compileLiteral(argument);
    assert.throws(() => extractor.document({ schema }), /non-finite.*JSON Schema/);
  });
}

test('finite and null literals preserve admission after JSON serialization', async () => {
  for (const [argument, accepted] of [['1.7976931348623157e308', Number.MAX_VALUE], ['-17', -17], ['null', null], ['"literal"', 'literal']]) {
    const schema = await compileLiteral(argument);
    const document = extractor.document({ schema });
    const decoded = JSON.parse(JSON.stringify(document));
    for (const value of [accepted, null, 0, 'other']) {
      assert.equal(validateDeclared(document, schema, value).success,
        validateDeclared(decoded, decoded.schema, value).success);
    }
    assert.equal(validateDeclared(decoded, decoded.schema, accepted).success, true);
  }
});
