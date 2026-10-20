import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

function findFiles(dir, filterRegex) {
  let results = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat && stat.isDirectory()) {
      if (file !== 'node_modules' && file !== 'dist' && file !== '.git') {
        results = results.concat(findFiles(fullPath, filterRegex));
      }
    } else if (filterRegex.test(file)) {
      results.push(fullPath);
    }
  }
  return results;
}

test('Part A1 — Zero visible USP labels in frontend components and pages', () => {
  const baseDir = fs.existsSync(path.resolve('src')) ? path.resolve('.') : path.resolve('frontend');
  const srcDir = path.join(baseDir, 'src');
  const files = findFiles(srcDir, /\.(jsx|js|html)$/);

  const visibleUspPattern = />\s*USP\s*\d+\s*<|["']Evidence Assessment \(USP \d+\)["']|["']\s*USP\s*\d+\s*["']/gi;
  const violations = [];

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split('\n');
    lines.forEach((line, idx) => {
      // Exclude comments
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
        return;
      }
      if (visibleUspPattern.test(line)) {
        violations.push({
          file: path.relative(process.cwd(), file),
          line: idx + 1,
          content: trimmed
        });
      }
    });
  }

  assert.equal(
    violations.length,
    0,
    `Found ${violations.length} visible USP label(s) in frontend: ${JSON.stringify(violations, null, 2)}`
  );
});

test('Part A2 — Assessment sections adopt SecureMailScope glass-card theme', () => {
  const baseDir = fs.existsSync(path.resolve('src')) ? path.resolve('.') : path.resolve('frontend');
  const ebaPath = path.join(baseDir, 'src/components/EvidenceBasedAssessment.jsx');
  const csaPath = path.join(baseDir, 'src/components/CryptographicStateAssessment.jsx');

  const ebaContent = fs.readFileSync(ebaPath, 'utf8');
  const csaContent = fs.readFileSync(csaPath, 'utf8');

  // Both should use className="glass-card"
  assert.ok(ebaContent.includes('className="glass-card evidence-assessment-card"'), 'EvidenceBasedAssessment must use glass-card');
  assert.ok(csaContent.includes('className="glass-card crypto-state-card"'), 'CryptographicStateAssessment must use glass-card');

  // Heavy saturated custom gradient overrides must be removed
  assert.ok(!ebaContent.includes('background: \'linear-gradient(135deg, rgba(15, 23, 42, 0.95)'), 'EvidenceBasedAssessment should not use conflicting linear-gradient');
  assert.ok(!csaContent.includes('background: \'linear-gradient(135deg, rgba(17, 24, 39, 0.95)'), 'CryptographicStateAssessment should not use conflicting linear-gradient');
});

test('Part B — Evidence navigation parameters standardized to &node=', () => {
  const baseDir = fs.existsSync(path.resolve('src')) ? path.resolve('.') : path.resolve('frontend');
  const ebaPath = path.join(baseDir, 'src/components/EvidenceBasedAssessment.jsx');
  const epPath = path.join(baseDir, 'src/pages/EvidenceProvenance.jsx');
  const pgPath = path.join(baseDir, 'src/components/ProvenanceGraph.jsx');

  const ebaContent = fs.readFileSync(ebaPath, 'utf8');
  const epContent = fs.readFileSync(epPath, 'utf8');
  const pgContent = fs.readFileSync(pgPath, 'utf8');

  // Evidence refs should use &node=
  assert.ok(ebaContent.includes('&node='), 'EvidenceBasedAssessment must link with &node=');

  // EvidenceProvenance must parse standard targetNodeParam
  assert.ok(epContent.includes('targetNodeParam'), 'EvidenceProvenance must resolve targetNodeParam');

  // ProvenanceGraph must have resolveGraphNode and centerOnNode
  assert.ok(pgContent.includes('resolveGraphNode'), 'ProvenanceGraph must use resolveGraphNode');
  assert.ok(pgContent.includes('centerOnNode'), 'ProvenanceGraph must center on node');
  assert.ok(pgContent.includes('unresolvedTarget'), 'ProvenanceGraph must handle unresolved target honestly');
});
