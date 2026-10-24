import { describe, expect, it } from 'vitest';

import { UrlSafetyEngine } from '../backend/src/url-safety';
import { RecoveryService } from '../backend/src/recovery';
import { validateSafeUrl } from '../backend/src/middleware';

describe('Application Security & Investigation Defenses (Modules 9, 10, 11 & 19)', () => {
  describe('SSRF & Malicious Input Sanitation (Module 19)', () => {
    it('blocks internal loopback and private IP addresses from inspection', () => {
      const urlSafety = new UrlSafetyEngine();
      const forbiddenTargets = [
        'http://127.0.0.1:8080/admin',
        'http://localhost:3000/api',
        'http://169.254.169.254/latest/meta-data/',
        'http://10.0.0.1/internal',
        'http://192.168.1.1/router',
        'http://[::1]/admin',
        'http://[::ffff:127.0.0.1]/admin',
        'http://[fc00::1]/admin',
      ];

      for (const target of forbiddenTargets) {
        const result = urlSafety.validateTargetUrl(target);
        expect(result.blocked, target).toBe(true);
        expect(result.isAllowed, target).toBe(false);
        expect(validateSafeUrl(target), target).toBe(false);
      }
    });

    it('rejects unsupported and dangerous URI protocols', () => {
      const urlSafety = new UrlSafetyEngine();
      const dangerousProtocols = [
        'file:///etc/passwd',
        'gopher://127.0.0.1:70/',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
      ];

      for (const target of dangerousProtocols) {
        expect(urlSafety.validateTargetUrl(target).blocked, target).toBe(true);
        expect(validateSafeUrl(target), target).toBe(false);
      }
    });
  });

  describe('Original security and recovery behaviors', () => {
    it('normalizes a public HTTPS target without fabricating an external threat result', () => {
      const result = new UrlSafetyEngine().analyze('https://google.com');
      expect(result.blocked).toBe(false);
      expect(result.isAllowed).toBe(true);
      expect(result.hostname).toBe('google.com');
      expect(result.riskScore).toBe(0);
    });

    it('generates real credential-exposure recovery steps without claiming compromise', () => {
      const assessment = new RecoveryService().assessIncident(
        'https://suspicious-login.test',
        'password_entered',
      );

      expect(assessment.recovery_steps.length).toBeGreaterThan(0);
      expect(assessment.recovery_steps.join(' ')).toContain('change the exposed password');
      expect(assessment.safety_verdict).toBe('unverified');
      expect(assessment.compromised_count).toBeNull();
      expect(assessment.evidence_note).toContain('No external');
    });

    it('derives delivery-channel guidance from the actual submitted incident', () => {
      const assessment = new RecoveryService().assessIncident(
        'WhatsApp message with a suspicious link',
        'clicked_link',
      );

      expect(assessment.delivery_channel).toContain('WhatsApp');
      expect(assessment.device_risk).toContain('No device compromise is established');
      expect(assessment.recovery_steps.length).toBeGreaterThan(0);
    });
  });
});
