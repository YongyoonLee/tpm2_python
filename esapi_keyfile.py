# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey

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

# ECC 키의 부모 템플릿을 정의합니다.
_parent_ecc_template = TPMT_PUBLIC(
    type=TPM2_ALG.ECC,  # ECC 알고리즘을 사용합니다.
    nameAlg=TPM2_ALG.SHA256,  # SHA-256 해시 알고리즘을 사용합니다.
    objectAttributes=TPMA_OBJECT.USERWITHAUTH  # 사용자 인증이 필요합니다.
                  | TPMA_OBJECT.RESTRICTED  # 제한된 키입니다.
                  | TPMA_OBJECT.DECRYPT  # 암호화된 데이터를 해독할 수 있습니다.
                  | TPMA_OBJECT.NODA  # DA(Delegate Administrator) 권한이 없습니다.
                  | TPMA_OBJECT.FIXEDTPM  # TPM에 고정된 키입니다.
                  | TPMA_OBJECT.FIXEDPARENT  # 부모 키가 고정되어 있습니다.
                  | TPMA_OBJECT.SENSITIVEDATAORIGIN  # 민감한 데이터의 출처입니다.
    ,
    authPolicy=b"",  # 인증 정책을 설정하지 않습니다.
    parameters=TPMU_PUBLIC_PARMS(
        eccDetail=TPMS_ECC_PARMS(
            symmetric=TPMT_SYM_DEF_OBJECT(
                algorithm=TPM2_ALG.AES,  # AES 알고리즘을 사용합니다.
                keyBits=TPMU_SYM_KEY_BITS(aes=128),  # 128비트 키를 사용합니다.
                mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),  # CFB 모드를 사용합니다.
            ),
            scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),  # 서명 체계를 설정하지 않습니다.
            curveID=TPM2_ECC.NIST_P256,  # NIST P-256 곡선을 사용합니다.
            kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),  # KDF를 설정하지 않습니다.
        ),
    ),
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
primary1, _, _, _, _ = ectx.create_primary(inSensitive, TPM2B_PUBLIC(publicArea=_parent_ecc_template))

# AES 대칭 키를 생성합니다.
priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublicAES)

# 생성한 키를 TSSPrivKey 객체로 변환합니다.
k1 = TSSPrivKey(priv, pub, empty_auth=True, parent=TPM2_RH.OWNER)

# 생성한 키를 PEM 형식으로 변환하고 파일에 저장합니다.
p1 = k1.to_pem()
f = open("p1.pem", "w")
f.write(p1.decode())
f.close()

# Primary 키의 컨텍스트를 플러시합니다.
ectx.flush_context(primary1)

# 저장된 PEM 파일을 읽어 TSSPrivKey 객체로 로드합니다.
f = open("p1.pem", "r")
k = TSSPrivKey.from_pem(f.read().encode("utf-8"))

# see https://github.com/tpm2-software/tpm2-pytss/issues/595
### its better to  load h2 primary and flush manually
# aesKeyHandle = k.load(ectx,password='')

# Primary 키를 다시 생성하고 AES 키를 로드합니다.
inSensitive = TPM2B_SENSITIVE_CREATE()
primary1, _, _, _, _ = ectx.create_primary(inSensitive, TPM2B_PUBLIC(publicArea=_parent_ecc_template))
aesKeyHandle = ectx.load(primary1, k.private, k.public)
ectx.flush_context(primary1)

# 초기화 벡터(IV)를 설정합니다.
ivIn = TPM2B_IV(bytes(bytearray.fromhex("4ca91f6bc6376a33a4ddb8a9c3cf5ea9")))

# 암호화할 데이터를 설정합니다.
inData = TPM2B_MAX_BUFFER(b"foo")

# 데이터를 AES-256-CFB 모드로 암호화합니다.
encrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData)
print(f"Encrypted Data: {encrypted}")

# 암호화된 데이터를 AES-256-CFB 모드로 복호화합니다.
decrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, encrypted)
print(f"Decrypted Data: {decrypted.marshal().decode("ascii")}")

# AES 키의 컨텍스트를 플러시합니다.
ectx.flush_context(aesKeyHandle)

# TPM API를 종료합니다.
ectx.close()