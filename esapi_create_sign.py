# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

# 해시 함수를 사용하기 위해 cryptography 라이브러리를 가져옵니다.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# 외부 cryptography 라이브러리로, SHA-256 해시 함수를 구현합니다.
def sha256(data: bytes) -> bytes:
    # SHA-256 해시 객체를 생성합니다.
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # 데이터를 해시 객체에 업데이트합니다.
    digest.update(data)
    # 해시를 완료하고 결과를 반환합니다.
    digest = digest.finalize()
    return digest

# TPM 2.0 API를 초기화합니다. 소프트웨어 TPM을 사용하려면, tcti="swtpm:port=2321"을 사용한다.
ectx = ESAPI(tcti=None)
# TPM을 초기화하고 모든 데이터를 지웁니다.
ectx.startup(TPM2_SU.CLEAR)

# RSA-2048 키의 공개 템플릿을 정의합니다.
inPublic = TPM2B_PUBLIC(
    TPMT_PUBLIC.parse(
        alg="rsa2048",  # RSA-2048 알고리즘을 사용합니다.
        objectAttributes=TPMA_OBJECT.USERWITHAUTH  # 사용자 인증이 필요합니다.
                      | TPMA_OBJECT.RESTRICTED  # 제한된 키입니다.
                      | TPMA_OBJECT.DECRYPT  # 암호화된 데이터를 해독할 수 있습니다.
                      | TPMA_OBJECT.FIXEDTPM  # TPM에 고정된 키입니다.
                      | TPMA_OBJECT.FIXEDPARENT  # 부모 키가 고정되어 있습니다.
                      | TPMA_OBJECT.SENSITIVEDATAORIGIN  # 민감한 데이터의 출처입니다.
    )
)

# RSA-2048 서명 및 암호화 키의 공개 템플릿을 정의합니다.
inPublicRSA = TPM2B_PUBLIC(
    TPMT_PUBLIC.parse(
        alg="rsa2048:rsassa:null",  # RSA-2048 서명 및 암호화 알고리즘을 사용합니다.
        objectAttributes=TPMA_OBJECT.USERWITHAUTH  # 사용자 인증이 필요합니다.
                      | TPMA_OBJECT.FIXEDPARENT  # 부모 키가 고정되어 있습니다.
                      | TPMA_OBJECT.FIXEDTPM  # TPM에 고정된 키입니다.
                      | TPMA_OBJECT.SENSITIVEDATAORIGIN  # 민감한 데이터의 출처입니다.
                      | TPMA_OBJECT.SIGN_ENCRYPT  # 서명 및 암호화가 가능합니다.
    )
)

# 민감한 데이터를 포함한 키 생성 템플릿을 정의합니다.
inSensitive = TPM2B_SENSITIVE_CREATE()

# Primary 키를 생성합니다.
primary1, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)

# RSA-2048 서명 및 암호화 키를 생성합니다.
priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublicRSA)

# 생성한 키를 로드합니다.
childHandle = ectx.load(primary1, priv, pub)

# Primary 키의 컨텍스트를 플러시합니다.
ectx.flush_context(primary1)

# 서명 체계를 정의합니다.
scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)

# 해시 알고리즘을 SHA-256으로 설정합니다.
scheme.details.any.hashAlg = TPM2_ALG.SHA256

# 해시 체크를 위한 유효성 검사 구조체를 정의합니다.
validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)

# TPM에서 데이터를 해시하고 티켓을 생성합니다.
digest, ticket = ectx.hash(b"fff", TPM2_ALG.SHA256, ESYS_TR.OWNER)

# 데이터에 서명을 생성합니다.
s = ectx.sign(childHandle, TPM2B_DIGEST(digest), scheme, validation)

# 서명의 알고리즘, 해시 알고리즘, 서명 값을 출력합니다.
print(f"Signing Algorithm: {s.sigAlg}")  # 서명 알고리즘
print(f"Hash Algorithm: {s.signature.rsassa.hash}")  # 해시 알고리즘
print(f"Signing Value: {s.signature.rsassa.sig}")  # 서명 값

# 서명을 검증합니다.
ectx.verify_signature(childHandle, TPM2B_DIGEST(digest), s)

# 키의 컨텍스트를 플러시합니다.
ectx.flush_context(childHandle)

# TPM API를 종료합니다.
ectx.close()