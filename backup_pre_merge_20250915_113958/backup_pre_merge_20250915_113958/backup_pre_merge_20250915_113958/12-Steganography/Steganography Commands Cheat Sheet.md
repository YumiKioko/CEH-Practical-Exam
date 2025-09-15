
---
# Steganography Commands Cheat Sheet

| Tool           | Action                  | Command Example                                            | Notes                                 |
| -------------- | ----------------------- | ---------------------------------------------------------- | ------------------------------------- |
| **Steghide**   | Embed data              | `steghide embed -cf cover.jpg -ef secret.txt`              | Prompts for passphrase                |
|                | Extract data            | `steghide extract -sf cover.jpg`                           | Prompts for passphrase                |
|                | Extract with output     | `steghide extract -sf cover.jpg -xf output.txt`            | Specify output filename               |
|                | Use passphrase          | `steghide embed -cf cover.jpg -ef secret.txt -p pass`      | Avoids prompt                         |
| **OutGuess**   | Embed data              | `outguess -k "pass" -d secret.txt -r cover.jpg output.jpg` | Requires JPEG only                    |
|                | Extract data            | `outguess -k "pass" -r output.jpg extracted.txt`           | Requires JPEG only                    |
| **Stegdetect** | Detect stego            | `stegdetect image.jpg`                                     | Detects stego in JPEG images          |
| **Foremost**   | Recover files           | `foremost -i suspect.jpg -o output_dir`                    | File carving / recovery               |
| **zsteg**      | Detect steg in PNG/JPEG | `zsteg -a image.png`                                       | Analyzes PNG/JPEG for hidden data     |
| **binwalk**    | Extract embedded data   | `binwalk -e firmware.bin`                                  | Extracts embedded files / firmware FS |
| **exiftool**   | View metadata           | `exiftool image.jpg`                                       | Check metadata for hidden info        |
| **strings**    | Extract readable text   | `strings file`                                             | Find hidden text                      |
| **xxd**        | Hex dump                | `xxd file`                                                 | Inspect file contents in hex          |

---
## Notes & Tips

- Always try **extract** commands on copies of files.
- Use **passphrase options** if known, otherwise tools will prompt.
- Start with detection tools like `stegdetect` or `zsteg` before extraction.
- Use `binwalk` to analyze and extract embedded files from binaries or images.
- `foremost` is useful for carving files appended to containers.
- Combine tools for better success in CTF or real-world steg investigations.
