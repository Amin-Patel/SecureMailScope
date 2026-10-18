import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../..');

test('Test 1: Inner Analysis navbar (.tabs-bar) matches main navbar pill glassmorphism', () => {
  const cssPath = path.join(projectRoot, 'frontend/src/index.css');
  const cssContent = fs.readFileSync(cssPath, 'utf8');

  // Verify .tabs-bar has pill border-radius and dark glass backdrop blur
  assert.match(cssContent, /\.tabs-bar\s*\{[^}]*border-radius:\s*999px;/);
  assert.match(cssContent, /\.tabs-bar\s*\{[^}]*backdrop-filter:\s*blur\(20px\);/);
  assert.match(cssContent, /\.tabs-bar\s*\{[^}]*box-shadow:/);

  // Verify .tab-btn has pill geometry and restrained active state
  assert.match(cssContent, /\.tab-btn\s*\{[^}]*border-radius:\s*999px;/);
  assert.match(cssContent, /\.tab-btn\.active\s*\{[^}]*background:\s*rgba\(255,\s*255,\s*255,\s*0\.14\);/);
});

test('Test 2: Reusable Analysis semantic status classes exist in index.css', () => {
  const cssPath = path.join(projectRoot, 'frontend/src/index.css');
  const cssContent = fs.readFileSync(cssPath, 'utf8');

  assert.ok(cssContent.includes('.analysis-card-neutral'), 'Missing .analysis-card-neutral');
  assert.ok(cssContent.includes('.analysis-card-violated'), 'Missing .analysis-card-violated');
  assert.ok(cssContent.includes('.analysis-card-satisfied'), 'Missing .analysis-card-satisfied');
  assert.ok(cssContent.includes('.analysis-card-warning'), 'Missing .analysis-card-warning');
  assert.ok(cssContent.includes('.analysis-evidence-tag'), 'Missing .analysis-evidence-tag');
});

test('Test 3: EvidenceBasedAssessment uses semantic status-aware classes instead of hardcoded uniform blue', () => {
  const compPath = path.join(projectRoot, 'frontend/src/components/EvidenceBasedAssessment.jsx');
  const compContent = fs.readFileSync(compPath, 'utf8');

  // Does not use uniform rgba(15, 23, 42, 0.7) for cards
  assert.ok(!compContent.includes("background: 'rgba(15, 23, 42, 0.7)'"), 'Found uniform dark blue card background');
  // Uses getOutcomeCardClass mapping to semantic classes
  assert.ok(compContent.includes('analysis-card-satisfied'), 'Missing satisfied card class');
  assert.ok(compContent.includes('analysis-card-violated'), 'Missing violated card class');
  assert.ok(compContent.includes('analysis-card-warning'), 'Missing warning card class');
  assert.ok(compContent.includes('analysis-card-neutral'), 'Missing neutral card class');
  // Uses analysis-evidence-tag for lineage tracing
  assert.ok(compContent.includes('analysis-evidence-tag'), 'Missing analysis-evidence-tag');
});

test('Test 4: CryptographicStateAssessment uses status-aware rule classes instead of uniform blue cards', () => {
  const compPath = path.join(projectRoot, 'frontend/src/components/CryptographicStateAssessment.jsx');
  const compContent = fs.readFileSync(compPath, 'utf8');

  // Does not use uniform rgba(15, 23, 42, 0.65) for rule cards
  assert.ok(!compContent.includes("background: 'rgba(15, 23, 42, 0.65)'"), 'Found uniform dark blue rule card background');
  // Uses getRuleCardClass mapping to semantic classes
  assert.ok(compContent.includes('analysis-card-satisfied'), 'Missing satisfied rule class');
  assert.ok(compContent.includes('analysis-card-violated'), 'Missing violated rule class');
  assert.ok(compContent.includes('analysis-card-warning'), 'Missing warning rule class');
  assert.ok(compContent.includes('analysis-card-neutral'), 'Missing neutral rule class');
});

test('Test 5: Analysis.jsx eliminated generic violet/indigo neon gradient buttons', () => {
  const pagePath = path.join(projectRoot, 'frontend/src/pages/Analysis.jsx');
  const pageContent = fs.readFileSync(pagePath, 'utf8');

  // Verify hardcoded linear-gradient(135deg, rgba(99, 102, 241, 0.25), rgba(168, 85, 247, 0.25)) is eliminated
  assert.ok(!pageContent.includes('rgba(99, 102, 241, 0.25), rgba(168, 85, 247, 0.25)'), 'Found neon gradient button in Analysis.jsx');
  // Verify glass buttons are used
  assert.ok(pageContent.includes('btn-action btn-secondary'), 'Missing btn-action btn-secondary');
});
