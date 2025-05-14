from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def sign_data_with_private_key(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Podpisuje dane podanym kluczem prywatnym RSA.
    
    :param data: Dane do podpisania (w bajtach)
    :param private_key_pem: Klucz prywatny w formacie PEM (bytes)
    :return: Podpis (signature) w bajtach
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )

    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def generate_rsa_key_pair():
    """
    Generuje losową parę kluczy RSA.
    Zwraca: (private_key_pem, public_key_pem)
    """
    # Generujemy losowy klucz RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serializacja klucza prywatnego do formatu PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializacja klucza publicznego do formatu PEM
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem