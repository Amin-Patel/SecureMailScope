import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

test('Drawer Scrollability & Flex Overflow Constraints Verification', async (t) => {
  await t.test('Test 1: ProvenanceGraph main canvas area has strict flex overflow constraints', () => {
    const graphFilePath = path.join(rootDir, 'src', 'components', 'ProvenanceGraph.jsx');
    const content = fs.readFileSync(graphFilePath, 'utf-8');

    // Verify main canvas area has minHeight: 0, overflow: 'hidden', height: '100%'
    assert.match(
      content,
      /minHeight:\s*0/,
      'ProvenanceGraph canvas area must contain minHeight: 0 to prevent child flex expansion'
    );
    assert.match(
      content,
      /overflow:\s*['"]hidden['"]/,
      'ProvenanceGraph canvas area must have overflow: hidden'
    );
  });

  await t.test('Test 2: ProvenanceDetailsDrawer has sticky header and scrollable body', () => {
    const drawerFilePath = path.join(rootDir, 'src', 'components', 'ProvenanceDetailsDrawer.jsx');
    const content = fs.readFileSync(drawerFilePath, 'utf-8');

    // Verify aside container
    assert.match(
      content,
      /provenance-details-drawer/,
      'ProvenanceDetailsDrawer must have provenance-details-drawer class'
    );
    assert.match(
      content,
      /maxHeight:\s*['"]100%['"]/,
      'ProvenanceDetailsDrawer aside must have maxHeight: 100%'
    );

    // Verify scrollable body
    assert.match(
      content,
      /provenance-drawer-scrollable/,
      'ProvenanceDetailsDrawer body must have provenance-drawer-scrollable class'
    );
    assert.match(
      content,
      /overflowY:\s*['"]auto['"]/,
      'ProvenanceDetailsDrawer body must have overflowY: auto'
    );
    assert.match(
      content,
      /overscrollBehavior:\s*['"]contain['"]/,
      'ProvenanceDetailsDrawer body must contain overscrollBehavior: contain'
    );
  });

  await t.test('Test 3: Custom scrollbar styling exists in index.css', () => {
    const cssFilePath = path.join(rootDir, 'src', 'index.css');
    const content = fs.readFileSync(cssFilePath, 'utf-8');

    assert.ok(
      content.includes('.provenance-drawer-scrollable'),
      'index.css must define styles for .provenance-drawer-scrollable'
    );
    assert.ok(
      content.includes('scrollbar-width: thin'),
      'index.css must define thin scrollbar for drawer'
    );
    assert.ok(
      content.includes('.provenance-drawer-scrollable::-webkit-scrollbar'),
      'index.css must define webkit scrollbar styles'
    );
  });
});
