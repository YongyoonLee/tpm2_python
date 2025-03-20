# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

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

# AES 대칭 키의 공개 템플릿을 정의합니다.
inPublicAES = TPM2B_PUBLIC(
    TPMT_PUBLIC.parse(
        alg="aes",  # AES 알고리즘을 사용합니다.
        objectAttributes=TPMA_OBJECT.USERWITHAUTH  # 사용자 인증이 필요합니다.
                      | TPMA_OBJECT.FIXEDPARENT  # 부모 키가 고정되어 있습니다.
                      | TPMA_OBJECT.FIXEDTPM  # TPM에 고정된 키입니다.
                      | TPMA_OBJECT.SENSITIVEDATAORIGIN  # 민감한 데이터의 출처입니다.
                      | TPMA_OBJECT.DECRYPT  # 암호화된 데이터를 해독할 수 있습니다.
                      | TPMA_OBJECT.SIGN_ENCRYPT  # 서명 및 암호화가 가능합니다.
    )
)

# 민감한 데이터를 포함한 키 생성 템플릿을 정의합니다.
inSensitive = TPM2B_SENSITIVE_CREATE()

# Primary 키를 생성합니다.
primary1, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)

# AES 대칭 키를 생성합니다.
priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublicAES)

# 생성한 AES 키를 로드합니다.
aesKeyHandle = ectx.load(primary1, priv, pub)

# Primary 키의 컨텍스트를 플러시합니다.
ectx.flush_context(primary1)

# 초기화 벡터(IV)를 설정합니다. 16바이트 길이여야 합니다.
ivIn = TPM2B_IV(b"thisis16bytes123")

# 암호화할 데이터를 설정합니다.
inData = TPM2B_MAX_BUFFER(b"fooo")

# 데이터를 AES-256-CFB 모드로 암호화합니다.
encrpyted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData)

# 암호화된 데이터를 16진수로 출력합니다.
print(f"Encrypted Data: {encrpyted.buffer.hex()}")
# 출력된 초기화 벡터를 16진수로 출력합니다.
print(f"IV: {outIV2.buffer.hex()}")

# 암호화된 데이터를 AES-256-CFB 모드로 복호화합니다.
decrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, encrpyted)

# 복호화된 데이터를 ASCII로 디코딩하여 출력합니다.
print(f"Decrypted Data: {decrypted.marshal().decode("ascii")}")

# AES 키의 컨텍스트를 플러시합니다.
ectx.flush_context(aesKeyHandle)