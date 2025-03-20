# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

# 임의의 문자열을 생성하기 위해 random 및 string 라이브러리를 가져옵니다.
import random, string

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

# 봉인할 데이터를 설정합니다.
seal_data = "secret".encode()

# 정책 경로를 생성합니다.
policy_path = f"/policy{random_uid()}"

# 키 경로를 생성합니다.
key_path = f"/HS/SRK/key{random_uid()}"

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
fapi_ctx.import_object(path=policy_path, import_data=pcr_policy)

# 데이터를 봉인합니다.
success = fapi_ctx.create_seal(
    path=key_path,  # 봉인할 키 경로를 설정합니다.
    data=seal_data,  # 봉인할 데이터를 설정합니다.
    policy_path=policy_path  # 정책 경로를 설정합니다.
)
# 봉인 성공 여부를 출력합니다.
print(success)

# PCR 데이터를 확장하려면 다음 코드를 사용합니다.
# pcr_data = b"abc"
# pcr_digest = sha256(pcr_data)
# fapi_ctx.pcr_extend(index=0, data=pcr_digest)

# 봉인된 데이터를 해제합니다.
unsealed_data = fapi_ctx.unseal(path=key_path)
# 해제된 데이터를 ASCII로 디코딩하여 출력합니다.
print(unsealed_data.decode('ascii'))

# 루트 디렉토리를 삭제하려면 다음 줄을 사용합니다.
# fapi_ctx.delete("/")

# FAPI를 종료합니다.
fapi_ctx.close()