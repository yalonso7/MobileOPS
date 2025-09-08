

-APK static analyzer with severity/reporting.
-Parses AndroidManifest.xml via available libraries (androguard, apkutils2, pyaxmlparser) and gracefully fall back to raw scanning.
-OWASP Mobile Top 10 and the extra checks, plus CLI to scan .apk files or directories.
-Android APK SAST tool mirroring your SAST_snake.py style: severities, per-line findings with code snippets, OWASP category, and remediation advice.
-parses APKs using multiple backends if available (androguard, apkutils2, pyaxmlparser) and gracefully falls back to raw ZIP scanning. It analyzes AndroidManifest.xml and candidate text files under assets/, res/xml/, res/raw/, META-INF/, etc.
-Checks include OWASP Mobile Top 10 2024 (M1–M10) plus extra items: Data Leakage, Hardcoded Secrets, Insecure Access Control, Path Traversal/Overwrite, Unprotected Endpoints, Unsafe Sharing. 
-It avoids noisy matches by stripping comments and limiting to candidate text files. 
-False-positive risk and malware-intent context were considered in patterns and guidance.


python SAST_AndroTX_55.py path\to\apk_or_directory -f text
# or JSON
python SAST_AndroTX_55.py path\to\apk_or_directory -f json -o report.json



