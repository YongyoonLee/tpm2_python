# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *
from tpm2_pytss.internal.templates import _ek
# from tpm2_pytss.tsskey import TSSPrivKey

'''
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_create -g sha256 -G aes128cfb -u aes.pub -r aes.prv -C primary.ctx -p pass

tpm2_load -C primary.ctx -u aes.pub -r aes.prv -c aes.ctx  
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c aes.ctx -o encrypt.out secret.dat -p pass
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_encryptdecrypt -Q --iv iv.bin -G cfb -c aes.ctx -d -o decrypt.out encrypt.out  -p pass
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
'''

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

# 외부에서 생성한 AES 키의 공개 키와 개인 키를 읽어옵니다.
with open("aes.pub", "rb") as file:
    pu = file.read()

with open("aes.prv", "rb") as file:
    pr = file.read()

## if you want, you can write the pub/priv to disk (eg pub.marshal())
# 읽어온 키를 TPM2B_PUBLIC 및 TPM2B_PRIVATE 객체로 변환합니다.
pub, _ = TPM2B_PUBLIC.unmarshal(pu)
priv, _ = TPM2B_PRIVATE.unmarshal(pr)

# 생성한 AES 키를 로드합니다.
aesKeyHandle = ectx.load(primary1, priv, pub)
ectx.flush_context(primary1)

# RSA-2048 키의 템플릿을 가져옵니다.
nv, tmpl = _ek.EK_RSA2048

# 민감한 데이터를 포함한 키 생성 템플릿을 정의합니다.
inSensitive = TPM2B_SENSITIVE_CREATE()

# Endorsement 키로 RSA-2048 Primary 키를 생성합니다.
handle, outpub, _, _, _ = ectx.create_primary(
    inSensitive, tmpl, ESYS_TR.ENDORSEMENT)

# HMAC 세션을 시작합니다.
hsess = ectx.start_auth_session(
    tpm_key=handle,  # HMAC 세션에 사용할 키를 설정합니다.
    bind=ESYS_TR.NONE,  # 바인딩 키를 사용하지 않습니다.
    session_type=TPM2_SE.HMAC,  # HMAC 세션을 생성합니다.
    symmetric=TPMT_SYM_DEF(
        algorithm=TPM2_ALG.AES,  # AES 알고리즘을 사용합니다.
        keyBits=TPMU_SYM_KEY_BITS(sym=128),  # 128비트 키를 사용합니다.
        mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),  # CFB 모드를 사용합니다.
    ),
    auth_hash=TPM2_ALG.SHA256,  # SHA-256 해시 알고리즘을 사용합니다.
)

# HMAC 세션의 속성을 설정합니다.
ectx.trsess_set_attributes(
    hsess, (TPMA_SESSION.DECRYPT | TPMA_SESSION.ENCRYPT)  # 세션에서 암호화 및 복호화를 허용합니다.
)

# 초기화 벡터(IV)를 설정합니다.
ivIn = TPM2B_IV(b"thisis16bytes123")

# 암호화할 데이터를 설정합니다.
inData = TPM2B_MAX_BUFFER(b"fooo")

# AES 키에 인증을 설정합니다.
ectx.tr_set_auth(aesKeyHandle, "pass")

# 데이터를 AES-128-CFB 모드로 암호화합니다.
encrypted, outIV2 = ectx.encrypt_decrypt_2(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData, session1=hsess)

# 암호화된 데이터와 출력된 IV를 출력합니다.
print(f"Encrypted Data: {encrypted.buffer.hex()}")
print(f"IV2: {outIV2.buffer.hex()}")

# HMAC 세션을 다시 시작합니다.
hsess = ectx.start_auth_session(
    tpm_key=handle,  # HMAC 세션에 사용할 키를 설정합니다.
    bind=ESYS_TR.NONE,  # 바인딩 키를 사용하지 않습니다.
    session_type=TPM2_SE.HMAC,  # HMAC 세션을 생성합니다.
    symmetric=TPMT_SYM_DEF(
        algorithm=TPM2_ALG.AES,  # AES 알고리즘을 사용합니다.
        keyBits=TPMU_SYM_KEY_BITS(sym=128),  # 128비트 키를 사용합니다.
        mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),  # CFB 모드를 사용합니다.
    ),
    auth_hash=TPM2_ALG.SHA256,  # SHA-256 해시 알고리즘을 사용합니다.
)

# HMAC 세션의 속성을 설정합니다.
ectx.trsess_set_attributes(
    hsess, (TPMA_SESSION.DECRYPT | TPMA_SESSION.ENCRYPT)  # 세션에서 암호화 및 복호화를 허용합니다.
)

# 암호화된 데이터를 AES-128-CFB 모드로 복호화합니다.
decrypted, outIV2 = ectx.encrypt_decrypt_2(aesKeyHandle, True, TPM2_ALG.CFB, ivIn, encrypted, session1=hsess)

# 복호화된 데이터를 출력합니다.
print(f"Decrypted Data: {decrypted.marshal().decode("ascii")}")

# 키와 세션의 컨텍스트를 플러시합니다.
ectx.flush_context(handle)
ectx.flush_context(aesKeyHandle)

# TPM API를 종료합니다.
ectx.close()