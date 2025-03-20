# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

# 해시 함수를 사용하기 위해 cryptography 라이브러리를 가져옵니다.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# 임의의 문자열을 생성하기 위해 random 및 string 라이브러리를 가져옵니다.
import random, string

# 임의의 ID를 생성하는 함수를 정의합니다.
def random_uid() -> str:
    """임의의 ID를 생성하여 예를 들어 고유한 키 이름으로 사용할 수 있습니다."""
    return "".join(random.choices(string.digits, k=10))

## after running fapi_export_tpm2.py, you'll have /tmp/key.pub /tmp/key.priv which you can load with:

# tpm2_createprimary -C o -c /tmp/primary.ctx -Q
# tpm2_load -C /tmp/primary.ctx -u /tmp/key.pub -r /tmp/key.priv -c /tmp/key.ctx
# tpm2_flushcontext -t
# echo -n "fff" > message.dat
# tpm2_sign -c key.ctx -g sha256 -o sig.rssa message.dat -f plain
# xxd -p sig.rssa 


# TPM 2.0 명령어 예제를 보여줍니다.
# 이 명령어들은 TPM에서 키를 생성하고 로드하는 과정을 설명합니다.

# SHA-256 해시 함수를 구현합니다.
def sha256(data: bytes) -> bytes:
    # SHA-256 해시 객체를 생성합니다.
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # 데이터를 해시 객체에 업데이트합니다.
    digest.update(data)
    # 해시를 완료하고 결과를 반환합니다.
    digest = digest.finalize()
    return digest

# FAPI 구성 설정을 정의합니다.
FAPIConfig(
    profile_name='P_RSA2048SHA256',  # 프로파일 이름을 설정합니다.
    # tcti="swtpm:port=2321",  # TPM 인터페이스를 설정합니다.
    temp_dirs=False,  # 임시 디렉토리를 사용하지 않습니다.
    ek_cert_less='yes',  # Endorsement 키 인증서가 필요하지 않습니다.
    system_dir="~/.local/share/tpm2-tss/system/keystore",  # 시스템 저장소 디렉토리를 설정합니다.
    profile_dir="/etc/tpm2-tss/fapi-profiles/",  # 프로파일 디렉토리를 설정합니다.
    user_dir="~/.local/share/tpm2-tss/user/keystore/"  # 사용자 저장소 디렉토리를 설정합니다.
)

# FAPI 컨텍스트를 생성합니다.
fapi_ctx = FAPI()
# FAPI를 초기화합니다.
fapi_ctx.provision()

# 임의의 서명 키 경로를 생성합니다.
key_path = f"/HS/SRK/sign{random_uid()}"

try:
    # 서명 키를 생성합니다. 이미 존재하는 경우 예외가 발생합니다.
    fapi_ctx.create_key(
        path=key_path,  # 키 경로를 설정합니다.
        type_='sign',  # 서명 키로 생성합니다.
        exists_ok=False  # 이미 존재하는 경우 생성을 허용하지 않습니다.
    )
except Exception as e:
    # 예외가 발생하면 출력합니다.
    print(e)
    pass  # 예외를 무시하고 계속 진행합니다.

# 루트 디렉토리에서 시작하여 모든 키를 나열합니다.
l = fapi_ctx.list(search_path="/HS/")
print(f"All Keys: {l}")  # 나열된 키를 출력합니다.

# 데이터를 SHA-256으로 해시합니다.
digest = sha256(b"fff")

# 해시된 데이터에 서명을 생성합니다.
sig, pub, cert = fapi_ctx.sign(
    path=key_path,  # 서명할 키 경로를 설정합니다.
    digest=digest,  # 해시된 데이터를 설정합니다.
    padding="rsa_ssa"  # 서명 패딩을 설정합니다.
)
# 서명 값을 16진수로 출력합니다.
print(f"Signature: {sig.hex()}")

# 서명을 검증합니다.
fapi_ctx.verify_signature(
    path=key_path,  # 서명한 키 경로를 설정합니다.
    digest=digest,  # 해시된 데이터를 설정합니다.
    signature=sig  # 서명 값을 설정합니다.
)

# 키의 TPM 블롭을 가져옵니다.
pub, priv, pol = fapi_ctx.get_tpm_blobs(path=key_path)

# 공개 키를 파일에 저장합니다.
with open("/tmp/key.pub", "wb") as binary_file:
    binary_file.write(pub.marshal())

# 개인 키를 파일에 저장합니다.
with open("/tmp/key.priv", "wb") as binary_file:
    binary_file.write(priv.marshal())

# 필요에 따라 공개 및 개인 키를 다시 로드할 수 있습니다.
# pub2, _ = TPM2B_PUBLIC.unmarshal(pub.marshal())
# priv2, _ = TPM2B_PRIVATE.unmarshal(priv.marshal())

# 루트 디렉토리를 삭제하려면 다음 줄을 사용합니다.
# fapi_ctx.delete("/")

# FAPI를 종료합니다.
fapi_ctx.close()