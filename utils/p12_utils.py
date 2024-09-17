import subprocess
import os

def change_p12_password(p12_file, old_password, new_password, output_file):
    try:
        command = [
            "openssl", "pkcs12", "-in", p12_file, "-out", "temp.pem",
            "-password", f"pass:{old_password}", "-nodes", "-legacy"
        ]
        subprocess.run(command, check=True)

        command = [
            "openssl", "pkcs12", "-export", "-in", "temp.pem", "-out", output_file,
            "-password", f"pass:{new_password}", "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC"
        ]
        subprocess.run(command, check=True)

        os.remove("temp.pem")
        print(f"Password changed successfully. New file saved as {output_file}")

    except subprocess.CalledProcessError as e:
        print(f"Failed to change password: {e}")
        sys.exit(1)
