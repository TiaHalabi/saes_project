import sys
import os
from saes_ctr    import encrypt_file, decrypt_file, ctr_process
from saes_attack import brute_force_ciphertext_only


def cmd_demo():
    import tempfile

    KEY   = 0x2B7E
    NONCE = 0xA3

    message = (
        b"S-AES CTR Mode Implementation\n"
        b"This file was encrypted using a 16-bit key.\n"
        b"The brute-force attacker will recover the key.\n"
    )

    with tempfile.TemporaryDirectory() as d:
        pt_path  = os.path.join(d, "plaintext.txt")
        enc_path = os.path.join(d, "ciphertext.enc")
        dec_path = os.path.join(d, "decrypted.txt")

        with open(pt_path, 'wb') as f:
            f.write(message)

        print("Step 1: Encrypting the file...")
        encrypt_file(pt_path, enc_path, KEY, NONCE)

        print("\nStep 2: Running brute-force attack...")
        with open(enc_path, 'rb') as f:
            data = f.read()
        candidates = brute_force_ciphertext_only(data[2:], data[0], magic_hint="txt_saes")

        if not candidates:
            print("Attack failed — no key found.")
            return

        recovered_key = candidates[0]
        print(f"Key recovered: 0x{recovered_key:04X}")

        print("\nStep 3: Decrypting with recovered key...")
        decrypt_file(enc_path, dec_path, recovered_key)

        with open(dec_path, 'rb') as f:
            recovered = f.read()

        print("\nRecovered message:")
        print(recovered.decode())

        if recovered == message:
            print("Success — decrypted file matches the original.")
        else:
            print("Error — decrypted file does not match.")


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "help":
        print("Usage:")
        print("  python main.py demo")
        print("  python main.py encrypt <input.txt> <output.enc> <key_hex> <nonce_hex>")
        print("  python main.py decrypt <input.enc> <output.txt> <key_hex>")
        print("  python main.py attack  <input.enc> [magic_hint]")
        return

    cmd = sys.argv[1].lower()

    if cmd == "demo":
        cmd_demo()

    elif cmd == "encrypt":
        if len(sys.argv) < 6:
            print("Usage: python main.py encrypt <input> <output> <key_hex> <nonce_hex>")
            return
        _, _, inp, out, key_s, nonce_s = sys.argv
        encrypt_file(inp, out, int(key_s, 16), int(nonce_s, 16))
        print("File encrypted successfully.")

    elif cmd == "decrypt":
        if len(sys.argv) < 5:
            print("Usage: python main.py decrypt <input.enc> <output.txt> <key_hex>")
            return
        _, _, inp, out, key_s = sys.argv
        decrypt_file(inp, out, int(key_s, 16))
        print("File decrypted successfully.")

    elif cmd == "attack":
        if len(sys.argv) < 3:
            print("Usage: python main.py attack <input.enc> [magic_hint]")
            return
        enc_path   = sys.argv[2]
        magic_hint = sys.argv[3] if len(sys.argv) > 3 else "txt_saes"
        with open(enc_path, 'rb') as f:
            data = f.read()
        brute_force_ciphertext_only(data[2:], data[0], magic_hint)

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()