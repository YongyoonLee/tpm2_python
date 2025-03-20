# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

# 해시 함수를 사용하기 위해 cryptography 라이브러리를 가져옵니다.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# SHA-256 해시 함수를 구현합니다.
def sha256(data: bytes) -> bytes:
    # SHA-256 해시 객체를 생성합니다.
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # 데이터를 해시 객체에 업데이트합니다.
    digest.update(data)
    # 해시를 완료하고 결과를 반환합니다.
    digest = digest.finalize()
    return digest

# 임의의 문자열을 생성하기 위해 random 및 string 라이브러리를 가져옵니다.
import random, string

# 임의의 ID를 생성하는 함수를 정의합니다.
def random_uid() -> str:
    """임의의 ID를 생성하여 예를 들어 고유한 키 이름으로 사용할 수 있습니다."""
    return "".join(random.choices(string.digits, k=10))

# FAPI 구성 설정을 정의합니다.
FAPIConfig(
    profile_name='P_RSA2048SHA256',  # 프로파일 이름을 설정합니다.
    # tcti=None,  # TPM 인터페이스를 설정합니다. 소프트웨어 TPM을 사용할 경우, tcti="swtpm:port=2321"로 설정한다.
    temp_dirs=False,  # 임시 디렉토리를 사용하지 않습니다.
    ek_cert_less='yes',  # Endorsement 키 인증서가 필요하지 않습니다.
    system_dir="~/.local/share/tpm2-tss/system/keystore",  # 시스템 저장소 디렉토리를 설정합니다.
    profile_dir="./profiles",  # 프로파일 디렉토리를 설정합니다.
    user_dir="~/.local/share/tpm2-tss/user/keystore/"  # 사용자 저장소 디렉토리를 설정합니다.
)

# FAPI 컨텍스트를 생성합니다.
fapi_ctx = FAPI()
# FAPI를 초기화합니다.
fapi_ctx.provision()

# 인증 콜백 함수를 정의합니다.
def password_callback(path, descr, user_data):
    # 콜백 함수가 호출될 때 경로, 설명, 사용자 데이터를 출력합니다.
    print(f"Callback: path={path}, descr={descr}, user_data={user_data}")
    # 사용자 데이터를 반환합니다.
    return user_data

# 임의의 키 경로를 생성합니다.
key_path = f"/HS/SRK/enc{random_uid()}"

# 서명 키를 생성합니다.
fapi_ctx.create_key(
    path=key_path,  # 키 경로를 설정합니다.
    type_='sign',  # 서명 키로 생성합니다.
    exists_ok=True,  # 이미 존재하는 경우에도 생성을 허용합니다.
    auth_value="password"  # 인증 값을 설정합니다.
)

# 인증 콜백 함수를 설정합니다.
fapi_ctx.set_auth_callback(password_callback, user_data=b"password")

# 데이터를 SHA-256으로 해시합니다.
digest = sha256(b"fff")

# 해시된 데이터에 서명을 생성합니다.
sig, pub, cert = fapi_ctx.sign(
    path=key_path,  # 서명할 키 경로를 설정합니다.
    digest=digest,  # 해시된 데이터를 설정합니다.
    padding="rsa_ssa"  # 서명 패딩을 설정합니다.
)
# 서명 값을 16진수로 출력합니다.
print(f"Signiture Value: {sig.hex()}")

# 임의의 키 경로를 생성합니다.
key_path = f"/HS/SRK/enc{random_uid()}"

# 암호화 키를 생성합니다.
fapi_ctx.create_key(
    path=key_path,  # 키 경로를 설정합니다.
    type_='decrypt',  # 암호화 키로 생성합니다.
    exists_ok=True,  # 이미 존재하는 경우에도 생성을 허용합니다.
    auth_value="password"  # 인증 값을 설정합니다.
)

# 인증 콜백 함수를 설정합니다.
fapi_ctx.set_auth_callback(password_callback, user_data=b"password")

# 데이터를 암호화합니다.
e = fapi_ctx.encrypt(
    path=key_path,  # 암호화할 키 경로를 설정합니다.
    plaintext='foo'  # 암호화할 데이터를 설정합니다.
)
# 암호화된 데이터를 16진수로 출력합니다.
print(f"Encrypted Data: {e.hex()}")

# 암호화된 데이터를 복호화합니다.
d = fapi_ctx.decrypt(
    path=key_path,  # 복호화할 키 경로를 설정합니다.
    ciphertext=e  # 복호화할 데이터를 설정합니다.
)
# 복호화된 데이터를 ASCII로 디코딩하여 출력합니다.
print(f"Decrypted Data: {d.decode('ascii')}")