// Source is parsed only; captured factories/getters/vendor code never execute.
// Clone mutations are local, and the shared AST control is restored in finally.
import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {openCorpus, objectProperty, findNodes} from '../scripts/original-contracts/source.mjs';
import {createSchemaExtractor} from '../scripts/original-contracts/schema.mjs';

const corpus = await openCorpus(fileURLToPath(new URL('..', import.meta.url)));
async function input() {
  const extractor = createSchemaExtractor(corpus);
  const {node, factory} = await extractor.declaration(387665, 'homeFeedRoutes');
  const route = node.arguments[0].properties.find(p => p.key.value === 'GET /home-feed').value;
  return {extractor, factory, query:objectProperty(route.type === 'CallExpression' ? route.arguments[1] : route, 'query')};
}
function maximum(node) {
  return findNodes(node, n => n.type === 'CallExpression' && n.callee.type === 'MemberExpression' &&
    n.callee.property.name === 'max' && n.arguments[0]?.type === 'NumericLiteral')[0].arguments[0];
}

test('a modified valid AST cannot change a source-bound Home-feed limit', async () => {
  const {extractor, factory, query} = await input();
  const changed = structuredClone(query);
  const bound = maximum(changed);
  assert.equal(bound.value, 200);
  bound.value = 201;
  assert.equal(factory.text(bound), '200');
  await assert.rejects(extractor.compile(changed, factory), /AST differs from source/);
});

test('constant recovery rejects a changed literal with the original source range', async () => {
  const {extractor, factory, query} = await input();
  const bound = structuredClone(maximum(query));
  bound.value = 201;
  await assert.rejects(extractor.constant(bound, factory), /AST differs from source/);
});

test('a mutated shared factory cannot seed a fresh extractor context', async () => {
  const {factory, query} = await input();
  const bound = maximum(query), original = bound.value;
  try {
    bound.value = 201;
    await assert.rejects(createSchemaExtractor(corpus).compile(query, factory), /AST differs from source/);
  } finally {
    bound.value = original;
  }
  // The retained source and the restored AST still compile afterward.
  assert.ok(await createSchemaExtractor(corpus).compile(query, factory));
});

test('unchanged clones and literal recovery retain source semantics', async () => {
  const {extractor, factory, query} = await input();
  assert.deepEqual(await extractor.compile(structuredClone(query), factory), await extractor.compile(query, factory));
  assert.equal(await extractor.constant(structuredClone(maximum(query)), factory), 200);
});
