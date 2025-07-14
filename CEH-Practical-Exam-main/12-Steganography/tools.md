# Steganography Tools

## Image Steganography

 Steghide
- steghide: Ocultação em imagens/áudio
- embed: Ocultar dados
- extract: Extrair dados

 Stegsolve
- stegsolve: Análise de imagens
- Filter Analysis: Análise de filtros
- Data Extraction: Extração de dados

 Binwalk
- binwalk: Análise de binários
- File Carving: Extração de arquivos
- Entropy Analysis: Análise de entropia

## Audio Steganography

 Audacity
- Audio Editor: Editor de áudio
- Spectral Analysis: Análise espectral
- Waveform Analysis: Análise de forma de onda


## Text Steganography

 Snow
- Whitespace Steganography: Esteganografia em espaços
- Text Hiding: Ocultação em texto

 Stegsnow
- Text Steganography: Esteganografia de texto
- Whitespace Encoding: Codificação de espaços

## File System Steganography

 Outguess
- JPEG Steganography: Esteganografia em JPEG
- Statistical Analysis: Análise estatística


# Scripts Úteis

 Steghide
steghide embed -cf image.jpg -ef secret.txt -p password
steghide extract -sf image.jpg -p password

 Binwalk
binwalk image.jpg
binwalk -e image.jpg
binwalk --dd='.*' image.jpg

 Strings
strings image.jpg
strings -a image.jpg | grep -i flag

 Exiftool
exiftool image.jpg
exiftool -all= image.jpg

 File analysis
file image.jpg
hexdump -C image.jpg | head
xxd image.jpg | head

 Stegsolve
java -jar stegsolve.jar

 Outguess
outguess -r image.jpg output.txt
outguess -k "password" -d output.txt image.jpg

 LSB analysis
zsteg image.png
zsteg -a image.png