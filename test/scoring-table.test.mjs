import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CHECKS } from '../src/check.mjs';
import { scoringTable, replaceTable } from '../scripts/scoring-table.mjs';

test('README scoring table matches the CHECKS export', () => {
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.equal(replaceTable(readme), readme, 'run: node scripts/scoring-table.mjs --write');
});

test('scoring table has one row per check plus header and total', () => {
  const lines = scoringTable().split('\n');
  assert.equal(lines.length, CHECKS.length + 3);
  for (const c of CHECKS) assert.ok(lines.some((l) => l.startsWith(`| \`${c.id}\` |`)), c.id);
});
