// src/utils/api.js
// Mock API utilities to simulate backend behavior for SecureMailScope front‑end.

/** Generate a random job ID (string) */
function generateJobId() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

/** Simulate uploading a PCAP file. Returns a Promise that resolves with a job ID */
export function uploadPcap(file) {
  console.log('Mock upload of', file?.name);
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(generateJobId());
    }, 500);
  });
}

/** Simulate fetching analysis data for a given job ID */
export function getAnalysis(jobId) {
  console.log('Fetching mock analysis data for job', jobId);
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        summary: {
          jobId,
          riskScore: 82,
          emailPackets: 1234,
          findingsCount: 4,
          sessions: 9,
          description: 'Automated analysis of captured traffic.'
        },
        findings: [
          {
            id: 1,
            severity: 'critical',
            severityLabel: 'Critical',
            title: 'Plaintext AUTH over SMTP',
            category: 'Authentication',
            endpoint: 'mail.example.com',
            desc: 'Credentials sent without encryption.',
            evidence: 'Packet 0x1a2b3c',
            reco: 'Enforce STARTTLS before AUTH.'
          },
          {
            id: 2,
            severity: 'high',
            severityLabel: 'High',
            title: 'Expired TLS Certificate',
            category: 'TLS',
            endpoint: 'mail.example.com',
            desc: 'Certificate expired on 2025-12-31.',
            evidence: 'Certificate #0xdeadbeef',
            reco: 'Renew certificate.'
          }
        ],
        sessions: [
          {
            id: 101,
            src: '192.168.1.10',
            dst: '192.168.1.20',
            protocol: 'SMTP',
            tlsVer: 'Plaintext',
            statusLabel: 'Weak',
            statusClass: 'badge-low',
            assess: 'Plaintext traffic detected.'
          },
          {
            id: 102,
            src: '192.168.1.30',
            dst: '192.168.1.40',
            protocol: 'SMTP',
            tlsVer: 'TLS 1.2',
            statusLabel: 'Secure',
            statusClass: 'badge-high',
            assess: 'Secure TLS session.'
          }
        ]
      });
    }, 400);
  });
}

/** Optional polling function – here it just resolves immediately */
export function pollAnalysis(jobId) {
  return getAnalysis(jobId);
}
