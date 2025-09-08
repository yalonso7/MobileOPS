#!/usr/bin/env python3
"""
Android APK SAST Tool - SAST_AndroTX_55
Static analysis security testing for Android APKs aligned with OWASP Mobile Top 10 (2024),
including supplemental checks (Data Leakage, Hardcoded Secrets, Insecure Access Control,
Path Traversal/Overwrite, Unprotected Endpoints, Unsafe Sharing).

This mirrors the reporting structure of SAST_snake.py: severities, code snippets, line numbers,
OWASP category, and actionable remediation guidance. It attempts multiple APK parsing backends
and gracefully degrades to raw scanning to avoid hard failures.
"""

import os
import re
import sys
import json
import argparse
import zipfile
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    line_number: int
    code_snippet: str
    recommendation: str
    owasp_category: str
    file_path: str


class APKParser:
    """APK parsing helper with multiple fallbacks.

    Attempts parsing with:
    - androguard (preferred)
    - apkutils2
    - pyaxmlparser
    Fallback: raw zip read; manifest may remain binary XML; scanning will be best-effort.
    """

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.backend = None
        self._zip: Optional[zipfile.ZipFile] = None
        self._manifest_text: Optional[str] = None
        self._manifest_lines: Optional[List[str]] = None
        self._init_backends()

    def _init_backends(self) -> None:
        # Try androguard
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
            self.backend = "androguard"
            self._ag_apk_cls = APK
            return
        except Exception:
            pass

        # Try apkutils2
        try:
            import apkutils2  # type: ignore
            self.backend = "apkutils2"
            self._apkutils2 = apkutils2
            return
        except Exception:
            pass

        # Try pyaxmlparser
        try:
            import pyaxmlparser  # type: ignore
            self.backend = "pyaxmlparser"
            self._pyaxmlparser = pyaxmlparser
            return
        except Exception:
            pass

        # Fallback to raw zip
        self.backend = "raw"

    def _ensure_zip(self) -> zipfile.ZipFile:
        if self._zip is None:
            self._zip = zipfile.ZipFile(self.apk_path, 'r')
        return self._zip

    def list_files(self) -> List[str]:
        try:
            return self._ensure_zip().namelist()
        except Exception:
            return []

    def read_file_text_best_effort(self, inner_path: str) -> str:
        try:
            with self._ensure_zip().open(inner_path, 'r') as f:
                data = f.read()
            # Try UTF-8, then latin-1
            try:
                return data.decode('utf-8')
            except Exception:
                try:
                    return data.decode('latin-1', errors='ignore')
                except Exception:
                    return ""
        except Exception:
            return ""

    def get_manifest_text(self) -> str:
        if self._manifest_text is not None:
            return self._manifest_text

        # Backend-specific attempts
        if self.backend == "androguard":
            try:
                apk_obj = self._ag_apk_cls(self.apk_path)
                # to_xml() returns a string of the manifest in XML
                self._manifest_text = apk_obj.get_android_manifest_axml().get_xml()  # type: ignore
            except Exception:
                self._manifest_text = ""

        elif self.backend == "apkutils2":
            try:
                parser = self._apkutils2.APK(self.apk_path)  # type: ignore
                self._manifest_text = parser.get_manifest()  # type: ignore (already decoded XML string)
            except Exception:
                self._manifest_text = ""

        elif self.backend == "pyaxmlparser":
            try:
                axml = self._pyaxmlparser.APK(self.apk_path)  # type: ignore
                self._manifest_text = axml.get_android_manifest_xml().toxml()  # type: ignore
            except Exception:
                self._manifest_text = ""

        else:  # raw fallback
            # Try reading AndroidManifest.xml and hope it is already XML (some builds include plain XML)
            self._manifest_text = self.read_file_text_best_effort('AndroidManifest.xml')

        if self._manifest_text is None:
            self._manifest_text = ""
        self._manifest_lines = self._manifest_text.split('\n') if self._manifest_text else []
        return self._manifest_text

    def get_manifest_lines(self) -> List[str]:
        if self._manifest_lines is None:
            self.get_manifest_text()
        return self._manifest_lines or []

    def iter_candidate_text_files(self) -> List[str]:
        """List candidate text files inside the APK for scanning.
        We include typical locations that are likely text: assets/, lib/ (rare), res/xml/*, res/raw/*, META-INF/*.
        Note: Many res/*.xml are binary AXML; read_file_text_best_effort handles decoding best-effort.
        """
        names = self.list_files()
        candidates: List[str] = []
        for n in names:
            lower = n.lower()
            if lower.endswith(('.xml', '.txt', '.json', '.yaml', '.yml', '.properties', '.cfg', '.ini', '.pem', '.crt', '.conf', '.js')):
                candidates.append(n)
            elif lower.startswith(('assets/', 'res/raw/', 'res/xml/', 'META-INF/')):
                # keep likely text regardless of extension
                candidates.append(n)
        return candidates


class MobileVulnerabilityDetector:
    """Detection engine for OWASP Mobile Top 10 and extras."""

    def __init__(self) -> None:
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict[str, Dict[str, Any]]:
        return {
            # M1: Improper Credential Usage
            'M1-001': {
                'name': 'Hardcoded credentials or tokens',
                'owasp': 'M1 - Improper Credential Usage',
                'severity': Severity.HIGH,
                'patterns': [
                    r'(api[_-]?key|access[_-]?key|secret|password|pwd|token)\s*[=:]\s*\"[^\"]{12,}\"',
                    r'Basic\s+[A-Za-z0-9+/=]{10,}',
                    r'Bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
                ],
                'description': 'Possible hardcoded secrets detected.',
                'recommendation': 'Remove secrets from client; use secure backend, key vaults, and short-lived tokens.'
            },
            'M1-002': {
                'name': 'Insecure SharedPreferences mode',
                'owasp': 'M1 - Improper Credential Usage',
                'severity': Severity.HIGH,
                'patterns': [r'MODE_WORLD_READABLE', r'MODE_WORLD_WRITEABLE', r'MODE_WORLD_WRITABLE'],
                'description': 'World-readable/writable SharedPreferences used.',
                'recommendation': 'Use MODE_PRIVATE and encrypt secrets (e.g., EncryptedSharedPreferences).'
            },

            # M2: Supply Chain
            'M2-001': {
                'name': 'Debuggable build enabled',
                'owasp': 'M2 - Inadequate Supply Chain Security',
                'severity': Severity.MEDIUM,
                'manifest_patterns': [r'android:debuggable\s*=\s*"true"'],
                'description': 'App is marked debuggable in manifest.',
                'recommendation': 'Disable debuggable in release builds. Enforce build-time checks (CI) to prevent leakage.'
            },
            'M2-002': {
                'name': 'Backup enabled by default',
                'owasp': 'M8 - Security Misconfiguration',
                'severity': Severity.MEDIUM,
                'manifest_patterns': [r'android:allowBackup\s*=\s*"true"'],
                'description': 'allowBackup is enabled.',
                'recommendation': 'Set android:allowBackup="false" for sensitive apps or restrict via BackupAgent.'
            },

            # M3: AuthN/Z
            'M3-001': {
                'name': 'Exported components without permission',
                'owasp': 'M3 - Insecure Authentication/Authorization',
                'severity': Severity.HIGH,
                'manifest_patterns': [
                    r'<activity[^>]*android:exported\s*=\s*"true"(?![^>]*android:permission)'
                    r'|<service[^>]*android:exported\s*=\s*"true"(?![^>]*android:permission)'
                    r'|<receiver[^>]*android:exported\s*=\s*"true"(?![^>]*android:permission)'
                    r'|<provider[^>]*android:exported\s*=\s*"true"(?![^>]*android:readPermission|[^>]*android:writePermission)'
                ],
                'description': 'Exported component without required permissions.',
                'recommendation': 'Restrict exported components or define proper permissions/signature protection levels.'
            },

            # M4: I/O Validation
            'M4-001': {
                'name': 'WebView JavaScript enabled or JS interface',
                'owasp': 'M4 - Insufficient Input/Output Validation',
                'severity': Severity.MEDIUM,
                'patterns': [r'setJavaScriptEnabled\(\s*true\s*\)', r'addJavascriptInterface\('],
                'description': 'Potential WebView attack surface increased.',
                'recommendation': 'Avoid enabling JS; if required, use strict allowlists, CSP, and review interfaces.'
            },
            'M4-002': {
                'name': 'Potential path traversal usage',
                'owasp': 'M4 - Insufficient Input/Output Validation',
                'severity': Severity.MEDIUM,
                'patterns': [r'\.\./', r'..\\'],
                'description': 'User-controlled file paths may allow traversal.',
                'recommendation': 'Normalize and validate paths; confine to app-internal directories.'
            },

            # M5: Insecure Communication
            'M5-001': {
                'name': 'Cleartext HTTP usage',
                'owasp': 'M5 - Insecure Communication',
                'severity': Severity.HIGH,
                'patterns': [r'http://[^\s\"\']+'],
                'manifest_patterns': [r'android:usesCleartextTraffic\s*=\s*"true"'],
                'description': 'Cleartext network endpoints detected.',
                'recommendation': 'Enforce HTTPS; configure Network Security Config to disallow cleartext.'
            },
            'M5-002': {
                'name': 'TrustManager/HostnameVerifier accepts all',
                'owasp': 'M5 - Insecure Communication',
                'severity': Severity.CRITICAL,
                'patterns': [
                    r'X509TrustManager[\s\S]*?checkServerTrusted\s*\(\s*[^)]*\)\s*\{\s*\}',
                    r'HostnameVerifier[\s\S]*?verify\s*\([^)]*\)\s*\{[\s\S]*?return\s+true\s*;[\s\S]*?\}'
                ],
                'description': 'SSL validation disabled (accepts any cert/host).',
                'recommendation': 'Use system default TrustManager; never return true blindly; enable certificate pinning.'
            },

            # M6: Privacy
            'M6-001': {
                'name': 'Sensitive permissions requested',
                'owasp': 'M6 - Inadequate Privacy Controls',
                'severity': Severity.MEDIUM,
                'manifest_patterns': [
                    r'android:name\s*=\s*"android.permission.READ_SMS"',
                    r'android:name\s*=\s*"android.permission.READ_CONTACTS"',
                    r'android:name\s*=\s*"android.permission.READ_CALL_LOG"',
                    r'android:name\s*=\s*"android.permission.ACCESS_FINE_LOCATION"'
                ],
                'description': 'App requests highly sensitive permissions.',
                'recommendation': 'Use least-privilege; provide purpose strings and runtime rationale; audit data flow.'
            },
            'M6-002': {
                'name': 'Logging of sensitive data',
                'owasp': 'M6 - Inadequate Privacy Controls',
                'severity': Severity.MEDIUM,
                'patterns': [r'Log\.(v|d|i|w|e)\s*\(', r'print(stack|ln)?\('],
                'description': 'Potential sensitive data written to logs.',
                'recommendation': 'Remove production logs or sanitize; never log PII, secrets, or tokens.'
            },

            # M7: Binary Protections
            'M7-001': {
                'name': 'Root/jailbreak or debugger checks disabled',
                'owasp': 'M7 - Insufficient Binary Protections',
                'severity': Severity.LOW,
                'patterns': [r'isDebuggerConnected\s*\(\s*\)\s*\|\|\s*false', r'android:debuggable\s*=\s*"true"'],
                'description': 'Possible lack of anti-tampering/anti-debugging controls.',
                'recommendation': 'Implement anti-tamper and root detection; obfuscation/shrinking in release builds.'
            },

            # M8: Misconfiguration
            'M8-001': {
                'name': 'ContentProvider exported without permissions',
                'owasp': 'M8 - Security Misconfiguration',
                'severity': Severity.HIGH,
                'manifest_patterns': [r'<provider[^>]*android:exported\s*=\s*"true"(?![^>]*Permission)'],
                'description': 'Provider may be accessible without authz.',
                'recommendation': 'Set read/writePermission or restrict to signature protection level.'
            },

            # M9: Insecure Data Storage
            'M9-001': {
                'name': 'Unencrypted local storage indicators',
                'owasp': 'M9 - Insecure Data Storage',
                'severity': Severity.MEDIUM,
                'patterns': [r'SQLiteOpenHelper', r'getSharedPreferences\(', r'openFileOutput\('],
                'description': 'Potential storage without encryption.',
                'recommendation': 'Encrypt at rest (SQLCipher, EncryptedFile, EncryptedSharedPreferences).'
            },

            # M10: Insufficient Cryptography
            'M10-001': {
                'name': 'Weak crypto algorithms',
                'owasp': 'M10 - Insufficient Cryptography',
                'severity': Severity.HIGH,
                'patterns': [r'MD5\b', r'SHA1\b', r'RC4\b', r'DES\b', r'AES/ECB'],
                'description': 'Weak or deprecated cryptographic primitives used.',
                'recommendation': 'Use SHA-256/512, AES-GCM/CTR; avoid ECB; use modern KDFs (PBKDF2, scrypt, Argon2).'
            },

            # Extras
            'X-001': {
                'name': 'Data Leakage risk',
                'owasp': 'Data Leakage',
                'severity': Severity.MEDIUM,
                'patterns': [r'\/sdcard\/', r'Environment\.getExternalStorage', r'WorldReadableFileProvider'],
                'description': 'External/world-readable storage usage may leak data.',
                'recommendation': 'Use app-internal storage; avoid external unless strictly necessary with correct flags.'
            },
            'X-002': {
                'name': 'Unprotected deep links / intent filters',
                'owasp': 'Unprotected Endpoints',
                'severity': Severity.HIGH,
                'manifest_patterns': [r'<intent-filter>[\s\S]*?<data[^>]*(android:scheme|android:host)[^>]*>[\s\S]*?</intent-filter>'],
                'description': 'Deep link endpoints may be exposed without authz.',
                'recommendation': 'Validate intents; require authz; use android:autoVerify and restrict exported components.'
            },
            'X-003': {
                'name': 'Path traversal/overwrite indicators',
                'owasp': 'Path Traversal',
                'severity': Severity.MEDIUM,
                'patterns': [r'File\s*\(\s*.*\)'],
                'description': 'File operations may be vulnerable if using untrusted input.',
                'recommendation': 'Validate file names; use canonical paths; avoid writing outside internal dirs.'
            },
            'X-004': {
                'name': 'Unsafe ContentProvider sharing',
                'owasp': 'Unsafe Sharing',
                'severity': Severity.MEDIUM,
                'manifest_patterns': [r'<provider[^>]*(grantUriPermissions|android:grantUriPermissions=\"true\")[^>]*>'],
                'description': 'Granting URI permissions broadly can leak data.',
                'recommendation': 'Use narrow path permissions and temporary grants with intent flags.'
            },
        }

    def _strip_xml_comments(self, text: str) -> str:
        try:
            return re.sub(r'<!--([\s\S]*?)-->', '', text)
        except Exception:
            return text

    def detect_in_manifest(self, manifest_text: str, apk_path: str) -> List[Finding]:
        findings: List[Finding] = []
        if not manifest_text:
            return findings
        cleaned = self._strip_xml_comments(manifest_text)
        lines = cleaned.split('\n')
        for rule_id, rule in self.rules.items():
            for pattern in rule.get('manifest_patterns', []) or []:
                regex = re.compile(pattern, re.IGNORECASE)
                for idx, line in enumerate(lines, 1):
                    if regex.search(line):
                        findings.append(Finding(
                            rule_id=rule_id,
                            title=rule['name'],
                            description=rule['description'],
                            severity=rule['severity'],
                            line_number=idx,
                            code_snippet=line.strip(),
                            recommendation=rule['recommendation'],
                            owasp_category=rule['owasp'],
                            file_path=f"{apk_path}!/AndroidManifest.xml"
                        ))
        return findings

    def detect_in_files(self, parser: APKParser) -> List[Finding]:
        findings: List[Finding] = []
        candidates = parser.iter_candidate_text_files()
        for inner_path in candidates:
            text = parser.read_file_text_best_effort(inner_path)
            if not text:
                continue
            # Strip obvious comments to reduce false positives
            stripped = re.sub(r'/\*([\s\S]*?)\*/', '', text)
            stripped = re.sub(r'//.*', '', stripped)
            lines = stripped.split('\n')
            for rule_id, rule in self.rules.items():
                for pattern in rule.get('patterns', []) or []:
                    try:
                        regex = re.compile(pattern)
                    except Exception:
                        continue
                    for idx, line in enumerate(lines, 1):
                        if regex.search(line):
                            findings.append(Finding(
                                rule_id=rule_id,
                                title=rule['name'],
                                description=rule['description'],
                                severity=rule['severity'],
                                line_number=idx,
                                code_snippet=line.strip()[:500],
                                recommendation=rule['recommendation'],
                                owasp_category=rule['owasp'],
                                file_path=f"{parser.apk_path}!/{inner_path}"
                            ))
        return findings

    def detect(self, apk_path: str) -> List[Finding]:
        parser = APKParser(apk_path)
        manifest_text = parser.get_manifest_text()
        findings = []
        # Manifest checks
        findings.extend(self.detect_in_manifest(manifest_text, apk_path))
        # File content checks
        findings.extend(self.detect_in_files(parser))
        return findings


class ReportGenerator:
    @staticmethod
    def generate_json_report(findings: List[Finding], target: str) -> Dict[str, Any]:
        return {
            'target': target,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(findings),
            'findings': [
                {
                    'rule_id': f.rule_id,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity.value,
                    'line_number': f.line_number,
                    'file_path': f.file_path,
                    'code_snippet': f.code_snippet,
                    'recommendation': f.recommendation,
                    'owasp_category': f.owasp_category
                }
                for f in findings
            ]
        }

    @staticmethod
    def generate_text_report(findings: List[Finding], target: str) -> str:
        if not findings:
            return f"No issues found in {target}\n"

        report = f"\n{'='*100}\n"
        report += f"ANDROID APK SECURITY ANALYSIS REPORT\n"
        report += f"Target: {target}\n"
        report += f"Total Findings: {len(findings)}\n"
        report += f"{'='*100}\n\n"

        groups: Dict[str, List[Finding]] = {}
        for f in findings:
            groups.setdefault(f.severity.value, []).append(f)

        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if sev in groups:
                report += f"\n{sev} SEVERITY FINDINGS:\n"
                report += f"{'-' * 40}\n"
                for fi in groups[sev]:
                    report += f"\n[{fi.rule_id}] {fi.title}\n"
                    report += f"File: {fi.file_path}\n"
                    report += f"Line {fi.line_number}: {fi.code_snippet}\n"
                    report += f"Description: {fi.description}\n"
                    report += f"Category: {fi.owasp_category}\n"
                    report += f"Recommendation: {fi.recommendation}\n"
                    report += f"{'-' * 40}\n"
        return report


class AndroidSASTTool:
    def __init__(self) -> None:
        self.detector = MobileVulnerabilityDetector()
        self.reporter = ReportGenerator()

    def scan_apk(self, apk_path: str) -> List[Finding]:
        try:
            return self.detector.detect(apk_path)
        except Exception as e:
            print(f"Error scanning {apk_path}: {e}")
            return []

    def scan_target(self, target_path: str) -> Dict[str, List[Finding]]:
        results: Dict[str, List[Finding]] = {}
        if os.path.isfile(target_path) and target_path.lower().endswith('.apk'):
            results[target_path] = self.scan_apk(target_path)
            return results

        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file.lower().endswith('.apk'):
                    full = os.path.join(root, file)
                    results[full] = self.scan_apk(full)
        return results

    def generate_report(self, findings_by_file: Dict[str, List[Finding]], output_format: str) -> str:
        if output_format == 'json':
            all_findings: List[Dict[str, Any]] = []
            for apk_path, findings in findings_by_file.items():
                rep = self.reporter.generate_json_report(findings, apk_path)
                for f in rep['findings']:
                    f['apk'] = apk_path
                    all_findings.append(f)
            return json.dumps({
                'total_apks': len(findings_by_file),
                'total_findings': len(all_findings),
                'findings': all_findings,
                'generated_at': datetime.now(timezone.utc).isoformat()
            }, indent=2)
        else:
            out = f"\n{'='*120}\nANDROID APK SECURITY ANALYSIS - SUMMARY\n{'='*120}\n"
            out += f"APKs scanned: {len(findings_by_file)}\n"
            out += f"Total findings: {sum(len(v) for v in findings_by_file.values())}\n"
            out += f"{'='*120}\n"
            for apk_path, findings in findings_by_file.items():
                out += self.reporter.generate_text_report(findings, apk_path)
            return out


def main() -> None:
    parser = argparse.ArgumentParser(description='Android APK SAST Tool (SAST_AndroTX_55)')
    parser.add_argument('target', help='APK file or directory to scan')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text', help='Report format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args = parser.parse_args()

    tool = AndroidSASTTool()
    results = tool.scan_target(args.target)
    report = tool.generate_report(results, args.format)

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"Report saved to {args.output}")
        except Exception as e:
            print(f"Failed to write report: {e}")
            print(report)
    else:
        print(report)


if __name__ == '__main__':
    main()


