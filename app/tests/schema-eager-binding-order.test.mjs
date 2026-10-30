import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, rm} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {openCorpus, sha256, RANGE_ENCODING, findNodes} from '../scripts/original-contracts/source.mjs';
import {createSchemaExtractor} from '../scripts/original-contracts/schema.mjs';

const app = fileURLToPath(new URL('..', import.meta.url));
const retained = await openCorpus(app);
const primitives = await Promise.all([876543, 599565, 408162].map(id => retained.factory(id)));
async function extractorFor(t, body) {
  const parent = path.join(app, '../work');
  await mkdir(parent, {recursive:true});
  const root = await mkdtemp(path.join(parent, 'eager-binding-'));
  t.after(() => rm(root, {recursive:true, force:true}));
  await mkdir(path.join(root, 'evidence/web/objects'), {recursive:true});
  await mkdir(path.join(root, 'recovered'));
  const custom = {id: 1, ids: [1], text: () => `(t,e,a)=>{const v=t.r(876543);${body}}`};
  let text = '';
  const modules = [];
  const source = 'evidence/web/objects/fixture.js', url = 'https://example.invalid/fixture.js';
  for (const factory of [...primitives, custom]) {
    const raw = factory.text();
    text += `(globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push(["fixture",${factory.ids.join(',')},`;
    const start = text.length;
    text += raw;
    modules.push({ids:factory.ids, sha256:sha256(raw), origins:[{source,url,start,end:text.length}]});
    text += ']);\n';
  }
  await writeFile(path.join(root, source), text);
  await writeFile(path.join(root, 'evidence/web/manifest.json'), JSON.stringify({records:[{
    path:source,url,status:200,bytes:Buffer.byteLength(text),sha256:sha256(text),
  }]}));
  await writeFile(path.join(root, 'recovered/modules.json'), JSON.stringify({rangeEncoding:RANGE_ENCODING,modules}));
  const corpus = await openCorpus(root);
  return {extractor:createSchemaExtractor(corpus), factory:await corpus.factory(1)};
}

for (const keyword of ['const', 'let', 'var']) {
  test(`reject eager ${keyword} aliases read before initialization`, async t => {
    const {extractor} = await extractorFor(t, `${keyword} early=later;${keyword} later=v.z.string();a.value=early;`);
    await assert.rejects(extractor.schema(1, 'value'), /uninitialized eager binding/);
  });
}

test('reject eager object shape and constant dependencies declared later', async t => {
  for (const body of [
    'const shape={name:later};const later=v.z.string();a.value=v.z.object(shape);',
    'const choices=[later];const later="one";a.value=v.z.enum(choices);',
    'const early=v.z.string().min(bound);const bound=3;a.value=early;',
    'const early=v.z.string();a.value=later;const later=early;',
    'const early=v.z.string().min(bound);var bound=3;a.value=early;',
    'const early=late.z.string();const late=t.r(876543);a.value=early;',
    'const early=a.later;a.later=v.z.string();a.value=early;',
  ]) {
    await t.test(body, async child => {
      const {extractor} = await extractorFor(child, body);
      await assert.rejects(extractor.schema(1, 'value'), /uninitialized eager binding/);
    });
  }
});

test('earlier initializers and multi-declarator left-to-right order remain supported', async t => {
  for (const body of [
    'const earlier=v.z.string();const later=earlier;a.value=later;',
    'const earlier=v.z.string(),later=earlier;a.value=later;',
    'const bound=3;const later=v.z.string().min(bound);a.value=later;',
  ]) {
    const {extractor} = await extractorFor(t, body);
    const schema = await extractor.schema(1, 'value');
    const document = extractor.document({value:schema});
    assert.equal(document.$defs['1.value'].$ref.startsWith('#/$defs/'), true);
  }
});

test('a deferred getter may refer to a declaration initialized later', async t => {
  const {extractor} = await extractorFor(t, 'const early=v.z.object({get child(){return later}});const later=v.z.string();a.value=early;');
  const schema = await extractor.schema(1, 'value');
  assert.ok(extractor.document({value:schema}).$defs['1.local:early']);
});

test('public compile and constant entries reject eager forward reads', async t => {
  const {extractor, factory} = await extractorFor(t, 'const early=v.z.string().min(bound);const bound=3;a.value=early;');
  const init = findNodes(factory.node.body, node => node.type === 'VariableDeclarator' && node.id.name === 'early')[0].init;
  await assert.rejects(extractor.compile(init, factory), /uninitialized eager binding/);
  await assert.rejects(extractor.constant(init.arguments[0], factory), /uninitialized eager binding/);
});
