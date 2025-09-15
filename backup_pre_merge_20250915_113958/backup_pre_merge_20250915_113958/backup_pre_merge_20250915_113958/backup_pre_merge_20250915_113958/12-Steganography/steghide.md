# Steghide

## Overview

**Steghide** is a command-line tool used to **hide (embed) data within various kinds of image and audio files** without noticeably altering the cover file. It supports encryption and compression, making it a popular choice for steganography in CTFs and security assessments.

---
## Supported File Types

- **Image:** BMP, JPEG
- **Audio:** WAV, AU

---
## Features

- Embeds arbitrary files into cover files.
- Supports **encryption** using a passphrase.
- Supports **compression** of embedded data.
- Minimal perceptible changes to the carrier file.
- Extraction requires the correct passphrase.

---
## Basic Usage

### Embed data into a cover file

```
steghide embed -cf coverfile.jpg -ef secret.txt
```

- `-cf` : Cover file (image or audio)
- `-ef` : Embedded file (the secret data to hide)«

You will be prompted to enter a passphrase (optional but recommended).

---
### Extract data from a steghide file

```
steghide extract -sf coverfile.jpg
```

- `-sf` : Stego file (the file containing hidden data)

You will be prompted for the passphrase used during embedding.

---
### Example Session

```
# Embed
steghide embed -cf image.jpg -ef secret.txt
Enter passphrase: ********
Embedding "secret.txt" in "image.jpg"...
```

```
# Extract
steghide extract -sf image.jpg
Enter passphrase: ********
wrote extracted data to "secret.txt".
```

---
## Useful Options

| Option       | Description                        |
| ------------ | ---------------------------------- |
| `-cf <file>` | Cover file                         |
| `-ef <file>` | Embedded file                      |
| `-sf <file>` | Stego file (file with hidden data) |
| `-xf <file>` | Extracted file name                |
| `-p <pass>`  | Passphrase (to avoid prompt)       |
| `-z <level>` | Compression level (0-9), default 6 |
| `-v`         | Verbose output                     |

---
## Tips & Tricks

- Use a **strong passphrase** to protect hidden data.
- Compression helps reduce the payload size and minimize changes.
- The cover file must be large enough to hold the embedded data.
- Always test extraction on a copy of the file.
- If no passphrase is given, no encryption is applied.

---
## Limitations

- Only certain image/audio formats supported.
- Detectable by advanced steganalysis tools if large data embedded.
- Compression and encryption add overhead.