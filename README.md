# Steganography Studio

Steganography Studio is a Python-based image steganography project that hides encrypted messages inside images and recovers them with the correct password.

It includes a desktop GUI, making it useful as a learning project, portfolio project, or mini security-tool demo.

## Features

- Hide secret text inside images using LSB steganography
- Protect hidden messages with password-based encryption using `cryptography`
- Encode and decode through a simple `tkinter` GUI
- Live image-capacity estimation before encoding
- Image preview, show/hide password toggle, and copy decoded message button
- UTF-8 message support for regular text and special characters
- Capacity validation and error handling for safer encoding
- Shared core logic for encryption, embedding, extraction, and validation

## Project Structure

- `app.py` - desktop GUI application
- `steganography_core.py` - shared steganography and encryption logic
- `requirements.txt` - project dependencies

## Installation

1. Create or activate your virtual environment.
2. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Run The App

Launch the GUI:

```powershell
python app.py
```

## How It Works

1. The message is encrypted using a password-derived key.
2. The encrypted payload is embedded into the image using least significant bit steganography.
3. The encoded image can later be decoded only with the correct password.

## Recommended Image Format

- Use `PNG` or `BMP` for encoded output.
- Do not save the encoded image as `JPEG`, because JPEG compression can damage hidden data.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
