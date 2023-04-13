from flask import Flask, request, render_template
import pefile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from flask import Flask, render_template, request
from secrets import token_bytes
import hashlib
import hmac

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

# DA1 : AES
key = token_bytes(16)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form['message']
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    result = {
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex(),
    }
    return render_template('aes_result.html', result=result)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    nonce = bytes.fromhex(request.form['nonce'])
    ciphertext = bytes.fromhex(request.form['ciphertext'])
    tag = bytes.fromhex(request.form['tag'])
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        result = {'plaintext': plaintext.decode('utf-8')}
    except ValueError:
        result = {'error': 'Invalid tag'}
    except KeyError:
        result = {'error': 'Decryption failed'}
    return render_template('aes_result.html', result=result)


# DA2 : DIGITAL SIGNATURE
@app.route('/generate_signature', methods=['POST'])
def generate_signature():
    message = request.form['message']
    key = request.form['key']
    signature = sign_message(message, key)
    return render_template('signature.html', message=message, signature=signature)

@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    message = request.form['message']
    key = request.form['key']
    signature = request.form['signature']
    computed_signature = sign_message(message, key)
    if computed_signature == signature:
        result = "valid"
    else:
        result = "invalid"
    return render_template('verification.html', message=message, signature=signature, result=result)

def sign_message(message, key):
    """
    Signs a message using HMAC-SHA256 with the given key.
    Returns the signature as a hex string.
    """
    message_bytes = message.encode('utf-8')
    key_bytes = key.encode('utf-8')
    signature = hmac.new(key_bytes, message_bytes, hashlib.sha256)
    return signature.hexdigest()


# DA3 : FILE HASHING
def hash_file(filename):
    """
    Computes the SHA256 hash of the given file and returns it as a hex string.
    """
    hasher = hashlib.sha256()
    with open(filename, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()

def verify_file_hash(filename, expected_hash):
    """
    Computes the SHA256 hash of the given file and compares it to the expected hash.
    Returns True if the hash matches, False otherwise.
    """
    actual_hash = hash_file(filename)
    return actual_hash == expected_hash

def generate_hash(text):
    """
    Computes the SHA256 hash of the given text and returns it as a hex string.
    """
    hasher = hashlib.sha256()
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()

def generate_file_hash(file):
    """
    Computes the SHA256 hash of the given file and returns it as a hex string.
    """
    hasher = hashlib.sha256()
    buf = file.read(65536)
    while len(buf) > 0:
        hasher.update(buf)
        buf = file.read(65536)
    return hasher.hexdigest()

@app.route('/upload', methods=['POST'])
def upload_file_and_verify_hash():
    uploaded_file = request.files['file']
    filename = uploaded_file.filename
    expected_hash = request.form['hash']
    uploaded_file.save(filename)
    if verify_file_hash(filename, expected_hash):
        return "File hash verified successfully."
    else:
        return "File hash verification failed."

@app.route('/generate', methods=['POST'])
def generate_hash_for_text():
    text = request.form['text']
    generated_hash = generate_hash(text)
    return f"The SHA256 hash of the text '{text}' is: {generated_hash}"

@app.route('/generate-file', methods=['POST'])
def generate_hash_for_file():
    uploaded_file = request.files['file']
    generated_hash = generate_file_hash(uploaded_file)
    return f"The SHA256 hash of the file '{uploaded_file.filename}' is: {generated_hash}"


# J COMP
unique_sections = set(['.text', '.rdata', '.data', '.rsrc', '.reloc'])

@app.route('/check_pe', methods=['POST'])
def check_pe():
    f = request.files['file']
    filename = f.filename
    f.save(filename)

    # Check the file
    try:
        result = check_file(filename)
    except Exception as e:
        result = f"Error: {str(e)}"

    return render_template('result.html', result=result)

def check_file(filename):
    # Load the PE file
    pe = pefile.PE(filename)

    # Check the conditions
    is_corrupted = 0
    total_check = 8

    # num_sections<=4
    if pe.FILE_HEADER.NumberOfSections <= 4:
        is_corrupted = is_corrupted + 1
        print("Number of sections is less than or equal to 4. File is corrupted.")

    # .sdata
    if ".sdata" in [section.Name.decode().strip('\x00') for section in pe.sections]:
        is_corrupted = is_corrupted + 1
        print("'.sdata' section found. File is corrupted.")

    # .data==0 or NULL
    if not pe.sections[0].Misc_VirtualSize and pe.sections[0].SizeOfRawData == 0:
        is_corrupted = is_corrupted + 1
        print("'.data' section is empty. File is corrupted.")

    # .rdata==0 or NULL
    if not pe.sections[1].Misc_VirtualSize and pe.sections[1].SizeOfRawData == 0:
        is_corrupted = is_corrupted + 1
        print("'.rdata' section is empty. File is corrupted.")

    # .rsrc==0 or NULL
    if not pe.sections[2].Misc_VirtualSize and pe.sections[2].SizeOfRawData == 0:
        is_corrupted = is_corrupted + 1
        print("'.rsrc' section is empty. File is corrupted.")

    # .reloc < .data
    # if pe.sections[5].PointerToRawData < pe.sections[0].PointerToRawData:
    #     is_corrupted = is_corrupted + 1
    #     print("'.reloc' section is located before '.data' section. File is corrupted.")

    # .orpc
    if ".orpc" in [section.Name.decode().strip('\x00') for section in pe.sections]:
        is_corrupted = is_corrupted + 1
        print("'.orpc' section found. File is corrupted.")

    # Check for sections
    exe_sections = set([section.Name.decode().rstrip('\x00') for section in pe.sections])
    different_sections = exe_sections - unique_sections
    if different_sections:
        is_corrupted = is_corrupted + 1
    
    return 100*is_corrupted / total_check

if __name__ == '__main__':
    app.run(debug=True)


