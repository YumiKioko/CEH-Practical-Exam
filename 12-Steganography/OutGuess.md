## OutGuess

## Overview

**OutGuess** is a universal steganographic tool that allows you to **hide data inside JPEG images** while trying to preserve the statistical properties of the image to avoid detection. It is commonly used in security and CTF challenges for embedding and extracting hidden messages.

---

## Features

- Embeds hidden data into **JPEG images**.
- Attempts to maintain image statistics to evade detection.
- Supports optional passphrase for encrypting hidden data.
- Extracts hidden data from stego-images.
- Works only on JPEG format (lossy compression).

---
## Basic Usage

### Embed data into a JPEG image

```
outguess -k "password" -d secret.txt -r input.jpg output.jpg
```

- `-k` : Passphrase/key to encrypt the embedded data (optional).
- `-d` : File containing data to embed.
- `-r` : Original cover JPEG file.
- `output.jpg` : New JPEG with hidden data embedded.

---
### Extract data from a JPEG image

```
outguess -k "password" -r output.jpg extracted.txt
```

- `-k` : Passphrase/key used for embedding.
- `-r` : Stego JPEG file containing hidden data.
- `extracted.txt` : Output file where extracted data will be saved.

---
### Example

Embedding

```
outguess -k "mysecret" -d message.txt -r cover.jpg stego.jpg
```

Extracting

```
outguess -k "mysecret" -r stego.jpg output.txt
```

---

## Notes

- The passphrase is optional but recommended to add encryption.    
- Since JPEG uses lossy compression, altering images may cause some quality degradation.
- OutGuess tries to minimize noticeable changes and preserve histogram of image data.
- Only works on JPEG images.

---

## Limitations

- Only supports JPEG format.    
- Data capacity limited by image size.
- Complex steganalysis may still detect embedded data.
