import secrets
import sys

import pyotp


def main():
    names = ["FLAG_SECRET", "SESSION_SECRET", "TOTP_ENC_KEY", "SHOP_SESSION_SECRET", "SERVICE_TOKEN", "MIGRATOR_DB_PASSWORD", "FLAGDESK_DB_PASSWORD", "VULNMART_DB_PASSWORD"]
    for n in names:
        print(f"{n}={secrets.token_hex(32)}")
    for i in (1, 2):
        secret = pyotp.random_base32()
        print(f"ORGANIZER_{i}_PASSWORD={secrets.token_urlsafe(18)}")
        print(f"ORGANIZER_{i}_TOTP_SECRET={secret}")
        print(f"# organizer {i} authenticator URI: {pyotp.TOTP(secret).provisioning_uri(name='organizer' + str(i), issuer_name='FlagDesk')}", file=sys.stderr)


if __name__ == "__main__":
    main()
