import base64
import hashlib
import os
import struct

import cv2
from cryptography.fernet import Fernet, InvalidToken


MAGIC = b"STEG"
HEADER_FORMAT = ">4s16sI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
BITS_PER_BYTE = 8


class SteganographyError(Exception):
    """Base project error for steganography operations."""


class CapacityError(SteganographyError):
    """Raised when the cover image cannot hold the payload."""


class InvalidImageError(SteganographyError):
    """Raised when an image cannot be read or decoded."""


def load_image(image_path):
    image = cv2.imread(image_path)
    if image is None:
        raise InvalidImageError(f"Unable to read image: {image_path}")
    return image


def derive_key(password, salt):
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        390000,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def encrypt_message(message, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(message.encode("utf-8"))
    return salt, token


def decrypt_message(salt, token, password):
    key = derive_key(password, salt)
    try:
        decrypted = Fernet(key).decrypt(token)
    except InvalidToken as exc:
        raise SteganographyError("Incorrect password or corrupted hidden data.") from exc
    return decrypted.decode("utf-8")


def build_payload(message, password):
    salt, token = encrypt_message(message, password)
    header = struct.pack(HEADER_FORMAT, MAGIC, salt, len(token))
    return header + token


def bytes_to_bits(data):
    bits = []
    for byte in data:
        for bit_index in range(7, -1, -1):
            bits.append((byte >> bit_index) & 1)
    return bits


def bits_to_bytes(bits):
    data = bytearray()
    for index in range(0, len(bits), BITS_PER_BYTE):
        chunk = bits[index:index + BITS_PER_BYTE]
        if len(chunk) < BITS_PER_BYTE:
            break
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        data.append(value)
    return bytes(data)


def max_payload_bytes(image):
    total_channels = image.size
    return total_channels // BITS_PER_BYTE


def get_image_capacity(image_path):
    image = load_image(image_path)
    return max_payload_bytes(image)


def validate_message_inputs(message, password):
    if not message:
        raise SteganographyError("Message cannot be empty.")
    if not password:
        raise SteganographyError("Password cannot be empty.")


def estimate_payload_size(message, password):
    validate_message_inputs(message, password)
    payload = build_payload(message, password)
    return len(payload)


def encode_image(input_image_path, output_image_path, message, password):
    validate_message_inputs(message, password)
    image = load_image(input_image_path)
    payload = build_payload(message, password)

    if len(payload) > max_payload_bytes(image):
        capacity = max_payload_bytes(image) - HEADER_SIZE
        safe_capacity = max(capacity, 0)
        raise CapacityError(
            f"Message is too large for this image. Approx available encrypted payload bytes: {safe_capacity}."
        )

    flat_image = image.reshape(-1)
    bits = bytes_to_bits(payload)

    encoded = flat_image.copy()
    for index, bit in enumerate(bits):
        encoded[index] = (encoded[index] & 0xFE) | bit

    encoded_image = encoded.reshape(image.shape)
    if not cv2.imwrite(output_image_path, encoded_image):
        raise InvalidImageError(f"Unable to write output image: {output_image_path}")

    return {
        "output_path": output_image_path,
        "image_capacity_bytes": max_payload_bytes(image),
        "payload_bytes": len(payload),
    }


def read_bits(flat_image, start_bit, bit_count):
    return [flat_image[index] & 1 for index in range(start_bit, start_bit + bit_count)]


def decode_image(image_path, password):
    if not password:
        raise SteganographyError("Password cannot be empty.")

    image = load_image(image_path)
    flat_image = image.reshape(-1)

    header_bits = read_bits(flat_image, 0, HEADER_SIZE * BITS_PER_BYTE)
    header_data = bits_to_bytes(header_bits)
    magic, salt, token_length = struct.unpack(HEADER_FORMAT, header_data)

    if magic != MAGIC:
        raise SteganographyError("No hidden message found in this image.")

    total_bytes = HEADER_SIZE + token_length
    required_bits = total_bytes * BITS_PER_BYTE
    if required_bits > len(flat_image):
        raise SteganographyError("Hidden data is incomplete or corrupted.")

    token_bits = read_bits(
        flat_image,
        HEADER_SIZE * BITS_PER_BYTE,
        token_length * BITS_PER_BYTE,
    )
    token = bits_to_bytes(token_bits)
    message = decrypt_message(salt, token, password)

    return {
        "message": message,
        "payload_bytes": total_bytes,
    }
