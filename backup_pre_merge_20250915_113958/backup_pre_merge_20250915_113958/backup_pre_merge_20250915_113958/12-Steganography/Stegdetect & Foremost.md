## Stegdetect

### Overview

Stegdetect is a command-line tool used for detecting steganography in **JPEG images**. It scans JPEG files to identify the presence of hidden data inserted by popular steganography tools.

### Features

- Detects various steganographic tools’ signatures (e.g., JSteg, F5).    
- Fast and lightweight.
- Useful as an initial detection step in forensic or CTF investigations.

```
stegdetect image.jpg
```

Example output:

```
image.jpg: Possible steg detection - JSteg algorithm
```

### Notes

- Works only on **JPEG** images.
- Only detects **presence**, does not extract hidden data.
- Can produce false positives or negatives, so confirm with other tools.

---
## Foremost

### Overview

**Foremost** is a forensic data recovery tool used to carve files from disk images or files. It can recover files hidden inside other files, useful for steganalysis or data carving in investigations.

### Features

- Recovers files based on headers, footers, and internal data structures.    
- Supports many file types: jpg, png, gif, pdf, doc, zip, etc.
- Can extract embedded files inside container files.

### Usage

```
foremost -i suspect_file.jpg -o output_dir
```

- `-i` : Input file (e.g., suspected stego file).
- `-o` : Output directory to save recovered files.

Example:

```
foremost -i stego_image.jpg -o recovered_files
```
### Notes

- Does not detect steganography but can recover files embedded inside.
- Good for uncovering hidden files appended or embedded.
- Works with raw data; useful in combination with steg tools.

---
## Summary

| Tool       | Purpose                      | Input          | Output           | Notes                          |
| ---------- | ---------------------------- | -------------- | ---------------- | ------------------------------ |
| Stegdetect | Detects stego signatures     | JPEG images    | Detection report | Only detects, no extraction    |
| Foremost   | Carves files from containers | Any file/image | Recovered files  | Recovers embedded/hidden files |
