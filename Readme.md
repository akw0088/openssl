base64_enc - Base64 Encode, useful to convert binary to ascii

base64_dec - Base64 Decode, convert base64 ascii to binary/text

rsa_enc - OpenSSL RSA encrypt with public key, max size 245 bytes

rsa_dec - OpenSSL RSA decrypt with private key

aes_enc - OpenSSL AES 256 bit CBC mode encrypt unlimited size, but symmetric key must be securely exchanged over a network

aes_dec - OpenSSL AES 256 bit CBC mode decrypt unlimited size, but symmetric key must be securely exchanged over a network

upload - Simple TCP file upload (listens for connections)

download - Simple TCP file download (Connects to ip/port)

aes_upload - AES encrypts file, sends RSA encrypted AES key to client securely with AES encrypted file (listens for connections)

aes_download - Downloads from server, uses private key to decrypt AES key, uses AES key to decrypt file (Connects to ip/port)

aes_upload_reverse - Same as aes_upload, but connects and uploads (connects to ip/port)

aes_download_reverse - Same as aes_download, but listens for connections and receives data (listens for connections)

getrandom - Gets random Hex digits from /dev/random (which may block) or /dev/urandom if a parameter is added. /dev/random is cryptographically secure, /dev/urandom is still cryptographically secure, but will reuse the entropy pool
