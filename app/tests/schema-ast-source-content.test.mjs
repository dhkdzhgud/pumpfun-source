// Source is parsed only; captured factories/getters/vendor code never execute.
// Clone mutations are local, and the shared AST control is restored in finally.
import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import path from 'node:path';
import {openCorpus, objectProperty, findNodes, sha256, RANGE_ENCODING} from '../scripts/original-contracts/source.mjs';
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

test('content binding preserves the authenticated source grammar', async t => {
  const parent = path.resolve(fileURLToPath(new URL('../..', import.meta.url)), 'work');
  await mkdir(parent, {recursive:true});
  const root = await mkdtemp(path.join(parent, 'ast-grammar-'));
  assert.ok(root.startsWith(parent + path.sep));
  t.after(() => rm(root, {recursive:true, force:true}));
  await mkdir(path.join(root, 'evidence/web/objects'), {recursive:true});
  await mkdir(path.join(root, 'recovered'));
  // yield is a valid binding in a non-strict script; reparsing as a module
  // would introduce a new strict-mode rejection absent from the source.
  const raw = '(t,e,a)=>{var yield=0;a.value=200}';
  const prefix = '(globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push(["fixture",1,';
  const text = prefix + raw + ']);';
  const source = 'evidence/web/objects/fixture.js', url = 'https://example.invalid/fixture.js';
  await writeFile(path.join(root, source), text);
  await writeFile(path.join(root, 'evidence/web/manifest.json'), JSON.stringify({records:[{
    path:source,url,status:200,bytes:Buffer.byteLength(text),sha256:sha256(text),
  }]}));
  await writeFile(path.join(root, 'recovered/modules.json'), JSON.stringify({rangeEncoding:RANGE_ENCODING,modules:[{
    ids:[1],sha256:sha256(raw),origins:[{source,url,start:prefix.length,end:prefix.length+raw.length}],
  }]}));
  const local = await openCorpus(root), factory = await local.factory(1);
  assert.equal(factory.capture.ast.program.sourceType, 'script');
  const value = findNodes(factory.node, n => n.type === 'NumericLiteral' && n.value === 200)[0];
  assert.equal(await createSchemaExtractor(local).constant(value, factory), 200);
});
