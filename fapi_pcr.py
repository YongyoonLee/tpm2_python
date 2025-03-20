# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

# 임의의 문자열을 생성하기 위해 random 및 string 라이브러리를 가져옵니다.
import random, string

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

# 임의의 ID를 생성하는 함수를 정의합니다.
def random_uid() -> str:
    """임의의 ID를 생성하여 예를 들어 고유한 키 이름으로 사용할 수 있습니다."""
    return "".join(random.choices(string.digits, k=10))

# FAPI 구성 설정을 정의합니다.
FAPIConfig(
    profile_name='P_RSA2048SHA256',  # 프로파일 이름을 설정합니다.
    # tcti="swtpm:port=2321",  # TPM 인터페이스를 설정합니다.
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

# 서명 키 경로를 설정합니다.
key_path = f"/HS/SRK/sign1111"

# 정책 경로를 설정합니다.
policy_path = f"/policy/pcr-policy"

# PCR 기반 정책을 정의합니다.
pcr_policy = """{
    "description": "Policy PCR 0 TPM2_ALG_SHA256",  # 정책 설명
    "policy": [
        {
            "type": "POLICYPCR",  # PCR 정책 유형
            "pcrs": [
                {
                    "pcr": 0,  # PCR 번호
                    "hashAlg": "TPM2_ALG_SHA256",  # 해시 알고리즘
                    "digest": "0000000000000000000000000000000000000000000000000000000000000000"  # PCR 해시 값
                }
            ]
        }
    ]
}
"""

# 정책을 TPM에 가져옵니다.
fapi_ctx.import_object(path=policy_path, import_data=pcr_policy, exists_ok=True)

# 서명 키를 생성하고 정책을 적용합니다.
fapi_ctx.create_key(
    path=key_path,  # 키 경로를 설정합니다.
    type_='sign',  # 서명 키로 생성합니다.
    exists_ok=True,  # 이미 존재하는 경우에도 생성을 허용합니다.
    policy_path=policy_path  # 정책 경로를 설정합니다.
)

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

# 루트 디렉토리를 삭제하려면 다음 줄을 사용합니다.
# fapi_ctx.delete("/")

# FAPI를 종료합니다.
fapi_ctx.close()