#!/usr/bin/env node
/**
 * Minify OWASP Dependency-Check JSON to shrink artifact size.
 * Usage: node security-tests/tools/minify-odc.js <in.json> <out.json>
 */
const fs = require('fs');

if (process.argv.length < 4) {
  console.error('Usage: node minify-odc.js <in.json> <out.json>');
  process.exit(2);
}

const [ , , inPath, outPath ] = process.argv;

function minify(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const clone = JSON.parse(JSON.stringify(obj));

  // Drop heavyweight sections
  delete clone.scanInfo;
  delete clone.projectInfo;

  if (Array.isArray(clone.dependencies)) {
    for (const dep of clone.dependencies) {
      delete dep.evidenceCollected;
      delete dep.vulnerableSoftware;
      delete dep.licenses;
      delete dep.vendorEvidence;
      delete dep.productEvidence;
      delete dep.versionEvidence;

      if (Array.isArray(dep.vulnerabilities)) {
        for (const v of dep.vulnerabilities) {
          if (Array.isArray(v.references)) v.references = v.references.slice(0, 5);
          if (Array.isArray(v.cwes)) v.cwes = v.cwes.slice(0, 3);
          if (typeof v.description === 'string' && v.description.length > 1200) {
            v.description = v.description.slice(0, 1200) + '…';
          }
        }
      }
    }
  }
  return clone;
}

const raw = fs.readFileSync(inPath, 'utf8');
const obj = JSON.parse(raw);
const out = minify(obj);
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`Minified ODC: ${inPath} -> ${outPath} (${(raw.length/1024/1024).toFixed(2)}MB -> ${(JSON.stringify(out).length/1024/1024).toFixed(2)}MB)`);
