# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

# base64 및 JSON 처리를 위해 필요한 라이브러리를 가져옵니다.
import base64
import json
from datetime import datetime, timedelta

# 임의의 문자열을 생성하기 위해 random 및 string 라이브러리를 가져옵니다.
import random, string

# 임의의 ID를 생성하는 함수를 정의합니다.
def random_uid() -> str:
    """임의의 ID를 생성하여 예를 들어 고유한 키 이름으로 사용할 수 있습니다."""
    return "".join(random.choices(string.digits, k=10))

# 해시 함수를 사용하기 위해 cryptography 라이브러리를 가져옵니다.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# 임의의 키 경로를 생성합니다.
key_path = f"/HS/SRK/key{random_uid()}"

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

# $ tpm2_createprimary -C o -c primary.ctx 
# name-alg:
#   value: sha256
#   raw: 0xb
# attributes:
#   value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt
#   raw: 0x30072
# type:
#   value: rsa
#   raw: 0x1
# exponent: 65537
# bits: 2048
# scheme:
#   value: null
#   raw: 0x10
# scheme-halg:
#   value: (null)
#   raw: 0x0
# sym-alg:
#   value: aes
#   raw: 0x6
# sym-mode:
#   value: cfb
#   raw: 0x43
# sym-keybits: 128


# tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx -Q
# tpm2_flushcontext -t
# tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
# tpm2_flushcontext -t

# $ echo '{"public":"'`xxd -p -c 1000 key.pub`'", "private": "'`xxd -p -c 1000 key.priv`'", "noauth":"YES"}' | jq '.'
# {
#   "public": "01180001000b00040072000000100014000b0800000000000100c4e9061e188c90f05a92a7820d91e8dcc3bbd784f738a0acc21dd3249940e001ef926dac486ba429f50d6c76b82013bbcc066cc1f54019182ff33d13da3c9962930dff3a0b55d775a9087b36ab7248a801abb8905097c61718959184c877a24d4aab00196bf2204d8eb5b856418ce78a382611904249c4309798240519dd21495b32450ba91c6dad7e09fd74c560382819cca9f96f8c8cb201ef274147e85d4f680b7ec2e32a54bdc1010cf7188415cd36a7575c7ef6569b1d7f2cd0bd993e2546a1617ffeb1f21015a015f2ebeff39d3da311917b3d6cdc5e8dbdb3e2725e45166cf3f3f93371b99a072d33d2ca0db1ad37cef2159bb83493df6dadaa5c1a4b",
#   "private": "00de002085ba735dd632280c670e2731b018e8faf221209e8784bea712b1e5578db076aa0010174bd9ceb675c5dbedb1fbc79533c6a6206d8e7f56a92cfb2a90e350484f25a1a0add8f939d5459d6d5c52c415fa4b1ad16da009abe2102d5a59a1283ab16f195d3bd4a04304a444a16c9eb5d81a80071cbef97ec4182f51ebc049341833432106c9508c1a4244559bc6d94feb1003d89873d24a149e8fe9e828fa4f72f6e64f70d82a3a1eb46b18723064cd884a3866e45e33cfdc1cf100d569baf2f8e99171ec9873cc2a2a7730e501856fce4e0bf251782ddcfcd341e4feac",
#   "noauth": "YES"
# }

# TPM 2.0 명령어 예제를 보여줍니다.
# 이 명령어들은 TPM에서 키를 생성하고 로드하는 과정을 설명합니다.

### important: replace with the pub/priv from your tpm
# JSON 형식의 키 데이터를 정의합니다.
key = """{
  "public": "01180001000b00040072000000100014000b0800000000000100c4e9061e188c90f05a92a7820d91e8dcc3bbd784f738a0acc21dd3249940e001ef926dac486ba429f50d6c76b82013bbcc066cc1f54019182ff33d13da3c9962930dff3a0b55d775a9087b36ab7248a801abb8905097c61718959184c877a24d4aab00196bf2204d8eb5b856418ce78a382611904249c4309798240519dd21495b32450ba91c6dad7e09fd74c560382819cca9f96f8c8cb201ef274147e85d4f680b7ec2e32a54bdc1010cf7188415cd36a7575c7ef6569b1d7f2cd0bd993e2546a1617ffeb1f21015a015f2ebeff39d3da311917b3d6cdc5e8dbdb3e2725e45166cf3f3f93371b99a072d33d2ca0db1ad37cef2159bb83493df6dadaa5c1a4b",
  "private": "00de002085ba735dd632280c670e2731b018e8faf221209e8784bea712b1e5578db076aa0010174bd9ceb675c5dbedb1fbc79533c6a6206d8e7f56a92cfb2a90e350484f25a1a0add8f939d5459d6d5c52c415fa4b1ad16da009abe2102d5a59a1283ab16f195d3bd4a04304a444a16c9eb5d81a80071cbef97ec4182f51ebc049341833432106c9508c1a4244559bc6d94feb1003d89873d24a149e8fe9e828fa4f72f6e64f70d82a3a1eb46b18723064cd884a3866e45e33cfdc1cf100d569baf2f8e99171ec9873cc2a2a7730e501856fce4e0bf251782ddcfcd341e4feac",
  "noauth": "YES"
}
"""
# JSON 형식의 키 데이터를 TPM에 가져옵니다.
fapi_ctx.import_object(path=key_path, import_data=key, exists_ok=False)

# SHA-256 해시 함수를 구현합니다.
def sha256(data: bytes) -> bytes:
    # SHA-256 해시 객체를 생성합니다.
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # 데이터를 해시 객체에 업데이트합니다.
    digest.update(data)
    # 해시를 완료하고 결과를 반환합니다.
    digest = digest.finalize()
    return digest

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