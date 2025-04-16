import subprocess
import secrets
import string
import tempfile
import os

def generate_password(length=24):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def add_jwk_admin_provisioner(name, admin_subject="step", admin_provisioner="Admin JWK", password_path="/etc/step-ca/password.txt"):
    random_password = generate_password()

    with tempfile.NamedTemporaryFile(delete=False, mode='w', prefix="pass_", suffix=".txt", dir="/tmp") as pass_file:
        pass_file.write(random_password)
        pass_file_path = pass_file.name

    try:
        cmd = [
            "step", "ca", "provisioner", "add", name,
            "--type", "JWK",
            "--create",
            f"--admin-subject={admin_subject}",
            f"--admin-password-file={password_path}",
            f"--admin-provisioner={admin_provisioner}",
            f"--password-file={pass_file_path}"
        ]
        print(f"Executing command: {' '.join(cmd)}")
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return {
            "success": True,
            "password": random_password,
            "stdout": output.decode(),
            "password_file": pass_file_path
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": e.output.decode(),
            "password_file": pass_file_path
        }
