# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *

# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
# printf '\x00\x00' > /tmp/unique.dat
# tpm2_createprimary -C o -G ecc  -g sha256 \
#     -c primary.ctx \
#     -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
# tpm2_create -g sha256 -G aes128cfb -u key.pub -r key.prv -C primary.ctx 

# tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx  
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
# echo "foo" > secret.dat
# openssl rand  -out iv.bin 16

# tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c key.ctx -o encrypt.out secret.dat
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
# tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c key.ctx -d -o decrypt.out encrypt.out
# tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

# TPM 2.0 명령어 예제를 보여줍니다.
# 이 명령어들은 TPM에서 ECC 키를 생성하고, 이를 사용하여 AES 키를 생성 및 로드하는 과정을 설명합니다.

# TPM 2.0 API를 초기화합니다. 소프트웨어 TPM을 사용하려면, tcti="swtpm:port=2321"을 사용한다.
ectx = ESAPI(tcti=None)
# TPM을 초기화하고 모든 데이터를 지웁니다.
ectx.startup(TPM2_SU.CLEAR)

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

# 민감한 데이터를 포함한 키 생성 템플릿을 정의합니다.
inSensitive = TPM2B_SENSITIVE_CREATE()

# Primary 키를 생성합니다.
primary1, _, _, _, _ = ectx.create_primary(inSensitive, TPM2B_PUBLIC(publicArea=_parent_ecc_template))

# 외부에서 생성한 AES 키의 공개 및 개인 키를 읽어옵니다.
with open("key.pub", "rb") as file:
    pu = file.read()

with open("key.prv", "rb") as file:
    pr = file.read()

## if you want, you can write the pub/priv to disk (eg pub.marshal())
# 읽어온 키를 TPM2B_PUBLIC 및 TPM2B_PRIVATE 객체로 변환합니다.
pub, _ = TPM2B_PUBLIC.unmarshal(pu)
priv, _ = TPM2B_PRIVATE.unmarshal(pr)

# 생성한 AES 키를 로드합니다.
aesKeyHandle = ectx.load(primary1, priv, pub)
ectx.flush_context(primary1)

# 초기화 벡터(IV)를 설정합니다.
ivIn = TPM2B_IV(bytes(bytearray.fromhex("4ca91f6bc6376a33a4ddb8a9c3cf5ea9")))

# 암호화할 데이터를 설정합니다.
inData = TPM2B_MAX_BUFFER(b"foo")

# 데이터를 AES-128-CFB 모드로 암호화합니다.
encrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData)
print(f"Encrypted Data: {encrypted}")

# 암호화된 데이터를 AES-128-CFB 모드로 복호화합니다.
decrypted, outIV2 = ectx.encrypt_decrypt(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, encrypted)
print(f"Decrypted Data: {decrypted.marshal().decode("ascii")}")

# AES 키의 컨텍스트를 플러시합니다.
ectx.flush_context(aesKeyHandle)

# TPM API를 종료합니다.
ectx.close()