import sys
import os

from saes_ctr import (encrypt_file, decrypt_file, ctr_process)
from saes_attack import (brute_force_ciphertext_only)


# ---------------------------------------------------
# Demonstration Function
# ---------------------------------------------------
# This function demonstrates the FULL workflow:
#
# 1. Encrypt a plaintext file
# 2. Perform brute-force attack
# 3. Recover the secret key
# 4. Decrypt the file again
#
# It shows why a 16-bit key is insecure.
# ---------------------------------------------------
def cmd_demo():

    import tempfile

    # -----------------------------------------------
    # Demo parameters
    # -----------------------------------------------
    KEY = 0x2B7E
    NONCE = 0xA3

    # Example plaintext message
    message = (
        b"S-AES CTR Mode Implementation\n"
        b"This file was encrypted using a 16-bit key.\n"
        b"The brute-force attacker will recover the key.\n"
    )

    # Create temporary working directory
    with tempfile.TemporaryDirectory() as d:

        pt_path = os.path.join(d, "plaintext.txt")
        enc_path = os.path.join(d, "ciphertext.enc")
        dec_path = os.path.join(d, "decrypted.txt")

        # -------------------------------------------
        # Create plaintext file
        # -------------------------------------------
        with open(pt_path, 'wb') as f:
            f.write(message)

        # -------------------------------------------
        # Step 1 — Encrypt file
        # -------------------------------------------
        print("Step 1: Encrypting the file...")

        encrypt_file(
            pt_path,
            enc_path,
            KEY,
            NONCE
        )

        # -------------------------------------------
        # Step 2 — Launch brute-force attack
        # -------------------------------------------
        print("\nStep 2: Running brute-force attack...")

        # Read encrypted file
        with open(enc_path, 'rb') as f:
            data = f.read()

        # data[0]   = nonce
        # data[2:]  = ciphertext
        candidates = brute_force_ciphertext_only(
            data[2:],
            data[0],
            magic_hint="txt_saes"
        )

        # If no key found, stop demo
        if not candidates:

            print("Attack failed — no key found.")

            return

        # Use first recovered key candidate
        recovered_key = candidates[0]

        print(f"Key recovered: 0x{recovered_key:04X}")

        # -------------------------------------------
        # Step 3 — Decrypt using recovered key
        # -------------------------------------------
        print("\nStep 3: Decrypting with recovered key...")

        decrypt_file(
            enc_path,
            dec_path,
            recovered_key
        )

        # Read recovered plaintext
        with open(dec_path, 'rb') as f:
            recovered = f.read()

        # -------------------------------------------
        # Display recovered message
        # -------------------------------------------
        print("\nRecovered message:")

        print(recovered.decode())

        # Verify recovered file matches original
        if recovered == message:

            print("Success — decrypted file matches the original.")

        else:
            print("Error — decrypted file does not match.")


# ---------------------------------------------------
# Main Command-Line Interface
# ---------------------------------------------------
# Handles user commands:
#
# - demo
# - encrypt
# - decrypt
# - attack
#
# Allows the project to be used like
# a small real encryption tool.
# ---------------------------------------------------
def main():

    # -----------------------------------------------
    # Show help message if no arguments provided
    # -----------------------------------------------
    if len(sys.argv) < 2 or sys.argv[1] == "help":

        print("Usage:")

        print("  python main.py demo")

        print(
            "  python main.py encrypt "
            "<input.txt> <output.enc> "
            "<key_hex> <nonce_hex>"
        )

        print(
            "  python main.py decrypt "
            "<input.enc> <output.txt> "
            "<key_hex>"
        )

        print(
            "  python main.py attack  "
            "<input.enc> [magic_hint]"
        )

        return

    # Read command name
    cmd = sys.argv[1].lower()


    # -----------------------------------------------
    # DEMO MODE
    # -----------------------------------------------
    # Runs full encryption + attack demonstration
    # -----------------------------------------------
    if cmd == "demo":

        cmd_demo()


    # -----------------------------------------------
    # ENCRYPT COMMAND
    # -----------------------------------------------
    # Encrypts a file using:
    # - provided key
    # - provided nonce
    # -----------------------------------------------
    elif cmd == "encrypt":

        # Validate number of arguments
        if len(sys.argv) < 6:

            print(
                "Usage: python main.py encrypt "
                "<input> <output> "
                "<key_hex> <nonce_hex>"
            )

            return

        # Extract arguments
        _, _, inp, out, key_s, nonce_s = sys.argv

        # Convert hexadecimal strings into integers
        key = int(key_s, 16)
        nonce = int(nonce_s, 16)

        # Encrypt file
        encrypt_file(inp, out, key, nonce)

        print("File encrypted successfully.")


    # -----------------------------------------------
    # DECRYPT COMMAND
    # -----------------------------------------------
    # Decrypts encrypted file using provided key
    # -----------------------------------------------
    elif cmd == "decrypt":

        # Validate arguments
        if len(sys.argv) < 5:

            print(
                "Usage: python main.py decrypt "
                "<input.enc> <output.txt> "
                "<key_hex>"
            )

            return

        # Extract arguments
        _, _, inp, out, key_s = sys.argv

        # Convert hexadecimal key into integer
        key = int(key_s, 16)

        # Decrypt file
        decrypt_file(inp, out, key)

        print("File decrypted successfully.")


    # -----------------------------------------------
    # ATTACK COMMAND
    # -----------------------------------------------
    # Launches ciphertext-only brute-force attack
    # using guessed file headers (magic bytes)
    # -----------------------------------------------
    elif cmd == "attack":

        # Validate arguments
        if len(sys.argv) < 3:

            print(
                "Usage: python main.py attack "
                "<input.enc> [magic_hint]"
            )

            return

        # Read encrypted file path
        enc_path = sys.argv[2]

        # Use optional magic hint
        magic_hint = (
            sys.argv[3]
            if len(sys.argv) > 3
            else "txt_saes"
        )

        # Read encrypted file
        with open(enc_path, 'rb') as f:
            data = f.read()

        # Run brute-force attack
        brute_force_ciphertext_only(
            data[2:],   # ciphertext
            data[0],    # nonce
            magic_hint
        )


    # -----------------------------------------------
    # UNKNOWN COMMAND
    # -----------------------------------------------
    else:

        print(f"Unknown command: {cmd}")


# ---------------------------------------------------
# Program Entry Point
# ---------------------------------------------------
# Python executes this section only when:
#
#     python main.py ...
#
# is launched directly from terminal.
# ---------------------------------------------------
if __name__ == "__main__":

    main()