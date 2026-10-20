import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const baseDir = fs.existsSync(path.resolve('src/pages/Analysis.jsx')) ? path.resolve('.') : path.resolve('frontend');
const analysisFilePath = path.join(baseDir, 'src/pages/Analysis.jsx');
const analysisContent = fs.readFileSync(analysisFilePath, 'utf-8');

test('Test 1: Overview section does not contain duplicate embedded EvidenceBasedAssessment', () => {
  // Extract activeTab === 'overview' section
  const overviewMatch = analysisContent.match(/\{activeTab === 'overview' && \([\s\S]*?<\/section>\s*\)/);
  assert.ok(overviewMatch, 'Overview section block must exist in Analysis.jsx');
  const overviewBlock = overviewMatch[0];

  assert.ok(
    !overviewBlock.includes('<EvidenceBasedAssessment'),
    'Overview section must NOT contain <EvidenceBasedAssessment component'
  );
});

test('Test 2: Overview section does not contain duplicate embedded CryptographicStateAssessment', () => {
  const overviewMatch = analysisContent.match(/\{activeTab === 'overview' && \([\s\S]*?<\/section>\s*\)/);
  assert.ok(overviewMatch, 'Overview section block must exist in Analysis.jsx');
  const overviewBlock = overviewMatch[0];

  assert.ok(
    !overviewBlock.includes('<CryptographicStateAssessment'),
    'Overview section must NOT contain <CryptographicStateAssessment component'
  );
});

test('Test 3: Overview section preserves Executive Summary and Security Findings Distribution', () => {
  const overviewMatch = analysisContent.match(/\{activeTab === 'overview' && \([\s\S]*?<\/section>\s*\)/);
  const overviewBlock = overviewMatch[0];

  assert.ok(
    overviewBlock.includes('Executive Summary'),
    'Overview must preserve the Executive Summary card'
  );
  assert.ok(
    overviewBlock.includes('Security Findings Distribution'),
    'Overview must preserve the Security Findings Distribution card'
  );
  assert.ok(
    overviewBlock.includes('Total Packets'),
    'Overview must preserve packet summary metrics'
  );
  assert.ok(
    overviewBlock.includes('View Evidence Provenance Graph'),
    'Overview must preserve the Evidence Provenance Graph action link'
  );
});

test('Test 4: Dedicated Evidence-Based Assessment tab preserves EvidenceBasedAssessment component', () => {
  const dedicatedEvidenceMatch = analysisContent.match(/\{activeTab === 'evidence_assessment' && \([\s\S]*?<\/section>\s*\)/);
  assert.ok(dedicatedEvidenceMatch, 'Dedicated evidence_assessment tab block must exist');
  const dedicatedBlock = dedicatedEvidenceMatch[0];

  assert.ok(
    dedicatedBlock.includes('<EvidenceBasedAssessment'),
    'Dedicated evidence_assessment tab must render <EvidenceBasedAssessment'
  );
  assert.ok(
    dedicatedBlock.includes('assessment={analysisData?.evidence_based_assessment}'),
    'Dedicated evidence_assessment tab must pass assessment prop'
  );
});

test('Test 5: Dedicated Cryptographic State tab preserves CryptographicStateAssessment component', () => {
  const dedicatedCryptoMatch = analysisContent.match(/\{activeTab === 'crypto' && \([\s\S]*?<\/section>\s*\)/);
  assert.ok(dedicatedCryptoMatch, 'Dedicated crypto tab block must exist');
  const dedicatedBlock = dedicatedCryptoMatch[0];

  assert.ok(
    dedicatedBlock.includes('<CryptographicStateAssessment'),
    'Dedicated crypto tab must render <CryptographicStateAssessment'
  );
  assert.ok(
    dedicatedBlock.includes('assessment={analysisData?.cryptographic_state_assessment}'),
    'Dedicated crypto tab must pass assessment prop'
  );
});

test('Test 6: Title bar badges provide direct quick navigation to dedicated assessment tabs', () => {
  assert.ok(
    analysisContent.includes("setActiveTab('crypto')"),
    'Title bar badge must allow jumping to dedicated Cryptographic State tab'
  );
  assert.ok(
    analysisContent.includes("setActiveTab('evidence_assessment')"),
    'Title bar badge must allow jumping to dedicated Evidence-Based Assessment tab'
  );
});
