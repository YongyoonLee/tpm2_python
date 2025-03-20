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
    profile_dir="./profiles",  # 프로파일 디렉토리를 설정합니다.
    user_dir="~/.local/share/tpm2-tss/user/keystore/"  # 사용자 저장소 디렉토리를 설정합니다.
)

# FAPI 컨텍스트를 생성합니다.
fapi_ctx = FAPI()
# FAPI를 초기화합니다.
fapi_ctx.provision()

# 임의의 키 경로를 생성합니다.
key_path = f"/HS/SRK/key{random_uid()}"

try:
    # PEM 형식의 개인 키를 가져와 TPM에 가져옵니다.
    key_private_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOHW00xKYNp0xv\ngbUDbedDyGDV6dM54TIBEiVZ0PPldACI6YBt8n+N5EnrrzkxEOEqTBQduhIQaGpe\nAgigU9MZPw1o1974Se7FIjRJA9nrvAkT2uEGAfq8wFgFnTvH7NbROGyaMEiwoAGI\nKAZfyXJ7Np095eLHSBx8xyP/j1OtrWw6M/duPR30X4bXdEZ8xbNbMsaz7+rYhuuU\n5XtUzJ1kcd5B6dlC05nq+k5GxQWYOa8rlCmqLHsUW9LCHABGFY+/srscEEywpFzC\nP7uimEwLsaKSkBPhJG5S0P4D3jDHBEuM8K7BXZXL7Y7hsozd1K/E2MBRrWhlsRZ/\ncgYS8S0zAgMBAAECggEALyun3wA0OoKzqP9HxGmmGCqnEr2pFCF4Fqum9aeu8a+7\nIZpCxKbPT1NUIYaf8Z050rrHjcgUM0IaObqAa+TTNn9qG7jvs+YDqYT670zc1ijZ\n8PvSLNROJF1mp55E3KvUu9wMarsrH5T21MjIMKrDMvScRtqyLEZSErJmiCmujlvt\nRJuUDzL3FFgax/RgS80FUWsmqGvBNL+guJfvYp4NwpSj+9xcV8Gaf8bI6CMIeWQd\nJ/vUGTT31yv2j5P5t1dnMfKdZSt2vFjdfizJKnhpj1sFgldwC+jSVzG9sRb1Xyb4\nZNWWJw27xZtp76xT92gIiU8AR+aO8wXdH5UcVmW56QKBgQD0h/lZttkNEoo4edV4\nelG3SMYEB/1fQ/ukG1EAVpOHfCpcuJEy0FOfsmQf5an4QF8L2EU50Td81HTnTJWK\nfLF9qAiIHa1mdUmtLjSelGgZOagG0BJhZeV6sdi+VayWhCbWmeEikS6zr+xwIv7S\nNuN83Gf3r9GMRvkbF8RI95Xc+wKBgQDXyDLWrWWdSjQEMa8D8U+eUzD6JrRlqa1z\nWptVcRXtQ+dvgPW36iz8lBo4DvTk1SsmEUeUO33YuO/timzCNqS9+2chtzSAJi3g\nJUpfIZoqwEbIpuJB5qr/rcUFHPtk4vGJeA7OLBJUsS3FLVoRCikf1jX9fHTLhzS3\nGSj/07YLKQKBgQCreH39zx488HdESwrKRNvwbnOMeB3QI9fdp9oRJqSlKQh7pGEN\nBNDe9zUGuQGLN3hu0eUZOgBy5HhliWqDhhTgTGhPKqBhbHWRnwj++opUxf1xaY66\nBb35X6ThMyqnEVw6uAULPEtHbWGa8K9HsX2sHNI6+WsztsEPoobds9++6QKBgQCQ\n2sFeIhsT4wtWQXAm6mizdU9srmztzmE1Df829Wpt0+bakKzjYN4AVP/g4BGASKXl\nsTXnCaTqxwOx5/ooynv/WXSbSpyA5qBnV0E86ZbP2jHqYzWCXfIvH50iWJle2Yah\n7SmrOCS6HBMIyfArfjGrQKcP2uug8cvumoJOcvZDOQKBgHoZhEHU/veIResRGF/y\nhPThSWJby8k4Rh7f//7SwZHAdG+zB2I81R92zOMhCwzdFIHQ2vattNpU/tW8dcHK\nXMZwbjhrGtF51NLkjHWTclP7KF2666gCGsFJ5qiJ9qxkgnAuqEwfSriU0xDMshxo\nsD808S+2pl4qks0EnHYC2uPi\n-----END PRIVATE KEY-----\n"
    fapi_ctx.import_object(path=key_path, import_data=key_private_pem)
except Exception as e:
    # 예외가 발생하면 출력합니다.
    print(e)
    pass  # 예외를 무시하고 계속 진행합니다.

# 루트 디렉토리에서 시작하여 모든 키를 나열합니다.
l = fapi_ctx.list(search_path="/HS/")
print(l)  # 나열된 키를 출력합니다.

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