---
name: export
description: Deobfuscate a file or report for final client delivery
user_invocable: true
args: "<file_path> [output_path]"
---

# Redact Export

The user wants to produce a deobfuscated version of a file for final client delivery. This reverses all redaction mappings so the report contains real values.

Steps:
1. Read the file at the given path using `redact_read_file` (or regular Read if the file contains only obfuscated data)
2. Call `redact_deobfuscate` on the content to restore all real values
3. Save the deobfuscated output to the specified output path, or default to `~/Desktop/<original_filename>`
4. Confirm the export location to the user
