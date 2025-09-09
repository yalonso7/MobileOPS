

 🎯 SAST_AndroTX_55 v1.2 - Key Improvements

1. Enhanced File Filtering
- Binary file exclusion: Comprehensive list of binary extensions (fonts, images, audio, video, archives, etc.)
- Smart file detection: Automatically skips `.ttf`, `.png`, `.mp3`, and other binary assets
- Targeted scanning: Only processes actual text/code files

2. Improved Path Traversal Detection
- Context-aware patterns: Looks for actual file operations like `File()`, `openFileOutput()`, etc.
- File extension validation: Requires file extensions or specific method calls
- Reduced noise: No more false positives from random `..` in binary data

3. Binary File Detection
- Content analysis: Detects binary files by checking null bytes and non-printable characters
- Smart thresholds: Skips files with >10% null bytes or >30% non-printable chars
- Prevents regex matching: Stops patterns from running on binary data

4. Context-Aware Pattern Matching
- Code file detection: Distinguishes between code and other text files
- False positive filtering: Multiple layers of context checks
- Rule-specific logic: Different rules apply different context requirements

5. Post-Processing Filters
- Final cleanup: Removes obvious false positives after detection
- Binary data filtering: Skips findings that look like binary data
- Meaningful snippet validation: Ensures code snippets are actually meaningful

   Usage

```bash
# Scan a single APK
python SAST_AndroTX_55_v1.2.py app.apk

# Scan directory of APKs
python SAST_AndroTX_55_v1.2.py /path/to/apks/

# Generate JSON report
python SAST_AndroTX_55_v1.2.py app.apk --format json --output report.json

# Verbose output
python SAST_AndroTX_55_v1.2.py app.apk --verbose
```

## ✅ Expected Results

The v1.2 version should now produce:
- No font file false positives (`.ttf` files excluded)
- Accurate path traversal detection (only real file operations)
- Clean, meaningful findings (no binary data noise)
- Context-aware results (appropriate for actual code files)

