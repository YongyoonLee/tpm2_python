# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *
from tpm2_pytss.internal.templates import _ek
#from tpm2_pytss.tsskey import TSSPrivKey

'''
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat
tpm2_flushcontexta -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_startauthsession -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_flushcontext session.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_create -g sha256 -G aes128cfb -u aes.pub -r aes.prv -C primary.ctx -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_load -C primary.ctx -u aes.pub -r aes.prv -n aes.name -c aes.ctx  

echo "foo" > secret.dat
openssl rand  -out iv.bin 16

tpm2_startauthsession --policy-session -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin

tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out   secret.dat  -p"session:session.dat"
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

## redo the policy again 
tpm2_startauthsession --policy-session -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin

tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out  -p"session:session.dat"
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

# 외부에서 생성한 AES 키의 공개 및 개인 키를 읽어옵니다.
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

# 초기화 벡터(IV)를 설정합니다.
ivIn = TPM2B_IV(b"thisis16bytes123")

# 암호화할 데이터를 설정합니다.
inData = TPM2B_MAX_BUFFER(b"fooo")

# AES 키에 인증을 설정합니다.
ectx.tr_set_auth(aesKeyHandle, "pass")

# PCR 23의 SHA-256 해시를 읽습니다.
pcrsels = TPML_PCR_SELECTION.parse("sha256:23")
_, _, digests, = ectx.pcr_read(pcrsels)
print(f"PCR 23 Hash: {digests[0].hex()}")  # PCR 23의 해시 값을 출력합니다.

# 정책 JSON을 정의합니다.
pol = {
    "description": "Policy PCR 23 TPM2_ALG_SHA256",  # 정책 설명
    "policy": [
        {
            "type": "POLICYPCR",  # PCR 정책 유형
            "pcrs": [
                {
                    "pcr": 23,  # PCR 번호
                    "hashAlg": "TPM2_ALG_SHA256",  # 해시 알고리즘
                    "digest": "{}".format(digests[0].hex())  # PCR 해시 값
                }
            ]
        }
    ]
}

# 정책 JSON을 문자열로 변환합니다.
polstr = json.dumps(pol).encode()

# 정책 세션을 시작합니다.
sess = ectx.start_auth_session(
    tpm_key=handle,  # 정책 세션에 사용할 키를 설정합니다.
    bind=ESYS_TR.NONE,  # 바인딩 키를 사용하지 않습니다.
    session_type=TPM2_SE.POLICY,  # 정책 모드의 세션을 생성합니다.
    symmetric=TPMT_SYM_DEF(
        algorithm=TPM2_ALG.AES,  # AES 알고리즘을 사용합니다.
        keyBits=TPMU_SYM_KEY_BITS(sym=128),  # 128비트 키를 사용합니다.
        mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),  # CFB 모드를 사용합니다.
    ),
    auth_hash=TPM2_ALG.SHA256,  # SHA-256 해시 알고리즘을 사용합니다.
)

# PCR 선택 콜백 함수를 정의합니다.
def pcr_cb(selection):
    # PCR 선택 구조체를 생성합니다.
    sel = TPMS_PCR_SELECTION(
        hash=TPM2_ALG.SHA256,  # SHA-256 해시 알고리즘을 사용합니다.
        sizeofSelect=selection.selections.pcr_select.sizeofSelect,  # 선택 크기를 설정합니다.
        pcrSelect=selection.selections.pcr_select.pcrSelect,  # PCR 선택 비트를 설정합니다.
    )
    out_sel = TPML_PCR_SELECTION((sel,))  # PCR 선택 목록을 생성합니다.

    # PCR 해시 목록을 생성합니다.
    digests = list()
    selb = bytes(sel.pcrSelect[0:sel.sizeofSelect])  # PCR 선택 비트를 바이트로 변환합니다.
    seli = int.from_bytes(reversed(selb), "big")  # 바이트를 정수로 변환합니다.
    for i in range(0, sel.sizeofSelect * 8):  # 각 PCR 비트에 대해
        if (1 << i) & seli:  # 비트가 설정되어 있으면
            dig = TPM2B_DIGEST(bytes([i]) * 32)  # PCR 해시를 생성합니다.
            digests.append(dig)  # 해시 목록에 추가합니다.
    out_dig = TPML_DIGEST(digests)  # 해시 목록을 반환합니다.

    return (out_sel, out_dig)

try:
    # 정책을 실행합니다.
    with policy(polstr, TPM2_ALG.SHA256) as p:
        p.set_callback(policy_cb_types.CALC_PCR, pcr_cb)  # PCR 계산 콜백을 설정합니다.
        p.calculate()  # 정책을 계산합니다.
        cjb = p.get_calculated_json()  # 계산된 정책 JSON을 가져옵니다.
        json_object = json.loads(cjb)  # JSON을 파싱합니다.
        print(json.dumps(json_object, indent=4))  # 계산된 정책을 출력합니다.
        p.execute(ectx, sess)  # 정책을 실행합니다.
except Exception as e:
    print(e)  # 예외가 발생하면 출력합니다.
    sys.exit(1)  # 프로그램을 종료합니다.

# 세션의 속성을 설정합니다.
ectx.trsess_set_attributes(
    sess, (TPMA_SESSION.DECRYPT | TPMA_SESSION.ENCRYPT)  # 세션에서 암호화 및 복호화를 허용합니다.
)

# 데이터를 AES-128-CFB 모드로 암호화합니다.
encrypted, outIV2 = ectx.encrypt_decrypt_2(aesKeyHandle, False, TPM2_ALG.CFB, ivIn, inData, session1=sess)

# 암호화된 데이터와 출력된 IV를 출력합니다.
print(f"Encrypted Data: {encrypted.buffer.hex()}")
print(f"IV2: {outIV2.buffer.hex()}")

# 키와 세션의 컨텍스트를 플러시합니다.
ectx.flush_context(handle)
ectx.flush_context(aesKeyHandle)

# TPM API를 종료합니다.
ectx.close()