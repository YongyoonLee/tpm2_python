# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

# TPM 2.0 API를 초기화합니다. 소프트웨어 TPM을 사용하려면, tcti="swtpm:port=2321"을 사용한다.
ectx = ESAPI(tcti=None)
# TPM을 초기화하고 모든 데이터를 지웁니다.
ectx.startup(TPM2_SU.CLEAR)

# https://github.com/salrashid123/tpm2/tree/master/hmac_import
# echo -n "change this password to a secret" | xxd -p -c 100
#   6368616e676520746869732070617373776f726420746f206120736563726574
# echo -n foo > data.in
# openssl dgst -sha256 -mac hmac -macopt hexkey:6368616e676520746869732070617373776f726420746f206120736563726574 data.in
#        HMAC-SHA256(data.in)= 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2

# HMAC 키 생성을 위한 비밀키 문자열을 정의합니다.
k = 'change this password to a secret'

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

# HMAC 키의 공개 템플릿을 정의합니다.
inPublicHMAC = TPM2B_PUBLIC(
    TPMT_PUBLIC.parse(
        alg="hmac",  # HMAC 알고리즘을 사용합니다.
        nameAlg="sha256",  # SHA-256 해시 알고리즘을 사용합니다.
        objectAttributes=TPMA_OBJECT.USERWITHAUTH  # 사용자 인증이 필요합니다.
                      | TPMA_OBJECT.FIXEDPARENT  # 부모 키가 고정되어 있습니다.
                      | TPMA_OBJECT.FIXEDTPM  # TPM에 고정된 키입니다.
                      | TPMA_OBJECT.SIGN_ENCRYPT  # 서명 및 암호화가 가능합니다.
    )
)

# 민감한 데이터를 포함한 키 생성 템플릿을 정의합니다.
inSensitive = TPM2B_SENSITIVE_CREATE()

# Primary 키를 생성합니다.
primary1, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)

# HMAC 키 생성을 위한 민감한 데이터를 포함한 키 생성 템플릿을 정의합니다.
inSensitiveHMAC = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE(data=TPM2B_SENSITIVE_DATA(k.encode("utf-8"))))

# HMAC 키를 생성합니다.
priv, pub, _, _, _ = ectx.create(primary1, inSensitiveHMAC, inPublicHMAC)

# 생성한 HMAC 키를 로드합니다.
childHandle = ectx.load(primary1, priv, pub)

# Primary 키의 컨텍스트를 플러시합니다.
ectx.flush_context(primary1)

# HMAC-SHA256을 계산합니다.
thmac = ectx.hmac(childHandle, b"foo", TPM2_ALG.SHA256)

# 계산된 HMAC 값을 16진수로 출력합니다.
print(f"HMAC Value: {thmac.buffer.hex()}")

# HMAC 키의 컨텍스트를 플러시합니다.
ectx.flush_context(childHandle)