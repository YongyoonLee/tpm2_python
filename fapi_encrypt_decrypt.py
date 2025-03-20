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
    temp_dirs=True,  # 임시 디렉토리를 사용합니다.
    ek_cert_less='yes',  # Endorsement 키 인증서가 필요하지 않습니다.
    profile_dir="./profiles"  # 프로파일 디렉토리를 설정합니다.
)

# FAPI 컨텍스트를 생성합니다.
fapi_ctx = FAPI()
# FAPI를 초기화합니다.
fapi_ctx.provision()

# TPM에서 8바이트의 무작위 데이터를 생성하고 16진수로 출력합니다.
print(str(fapi_ctx.get_random(8).hex()))

# 암호화 키를 생성합니다.
fapi_ctx.create_key(
    path='/HS/SRK/enc1',  # 키 경로를 설정합니다.
    type_='decrypt',  # 암호화 키로 생성합니다.
    exists_ok=True  # 이미 존재하는 경우에도 생성을 허용합니다.
)

# 데이터를 암호화합니다.
e = fapi_ctx.encrypt(
    path='/HS/SRK/enc1',  # 암호화할 키 경로를 설정합니다.
    plaintext='foo'  # 암호화할 데이터를 설정합니다.
)
# 암호화된 데이터를 16진수로 출력합니다.
print(f"Encrypted Data: {e.hex()}")

# 암호화된 데이터를 복호화합니다.
d = fapi_ctx.decrypt(
    path='/HS/SRK/enc1',  # 복호화할 키 경로를 설정합니다.
    ciphertext=e  # 복호화할 데이터를 설정합니다.
)
# 복호화된 데이터를 ASCII로 디코딩하여 출력합니다.
print(f"Decrypted Data: {d.decode('ascii')}")

# 루트 디렉토리를 삭제합니다.
fapi_ctx.delete("/")

# FAPI를 종료합니다.
fapi_ctx.close()