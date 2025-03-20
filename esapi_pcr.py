# tpm2_pytss 라이브러리를 가져옵니다.
from tpm2_pytss import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# SHA-256 해시 함수를 구현합니다.
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

# https://github.com/tpm2-software/tpm2-pytss/issues/504

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
inSensitive = TPM2B_SENSITIVE_CREATE(
    TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(""))  # 사용자 인증을 위한 빈 비밀번호를 설정합니다.
)

# 대칭 암호화 알고리즘을 정의합니다.
sym = TPMT_SYM_DEF(
    algorithm=TPM2_ALG.XOR,  # XOR 알고리즘을 사용합니다.
    keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),  # SHA-256 해시를 사용하여 키를 생성합니다.
    mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),  # CFB 모드를 사용합니다.
)

# Primary 키를 생성합니다.
primary1, _, _, _, _ = ectx.create_primary(inSensitive, inPublic)

# 인증 세션을 시작합니다.
session = ectx.start_auth_session(
    tpm_key=ESYS_TR.NONE,  # TPM 키를 사용하지 않습니다.
    bind=ESYS_TR.NONE,  # 바인딩 키를 사용하지 않습니다.
    session_type=TPM2_SE.TRIAL,  # 시도 모드의 세션을 생성합니다.
    symmetric=sym,  # 대칭 암호화 알고리즘을 사용합니다.
    auth_hash=TPM2_ALG.SHA256,  # SHA-256 해시 알고리즘을 사용합니다.
)

# $ tpm2_pcrread sha256:23
#   sha256:
#     23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

# PCR 23의 SHA-256 해시를 읽습니다.
pcrsels = TPML_PCR_SELECTION.parse("sha256:23")
_, _, digests, = ectx.pcr_read(pcrsels)
print(f"PCR 23: {digests[0].hex()}")  # PCR 23의 해시 값을 출력합니다.

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

# PCR 정책을 설정합니다.
ectx.policy_pcr(
    session, TPM2B_DIGEST(), TPML_PCR_SELECTION.parse("sha256:23")
)

# 정책 다이제스트를 가져옵니다.
policyDigest = ectx.policy_get_digest(session)
ectx.flush_context(session)

# RSA 키의 공개 템플릿에 정책 다이제스트를 설정합니다.
inPublicRSA.publicArea.authPolicy = policyDigest

# RSA 키를 생성합니다.
priv, pub, _, _, _ = ectx.create(primary1, inSensitive, inPublicRSA)
childHandle = ectx.load(primary1, priv, pub)
ectx.flush_context(primary1)

# 데이터를 SHA-256으로 해시합니다.
digest = sha256(b"fff")

# 서명 체계를 정의합니다.
scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
scheme.details.any.hashAlg = TPM2_ALG.SHA256  # SHA-256 해시 알고리즘을 사용합니다.
validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)

# TPM에서 데이터를 해시하고 티켓을 생성합니다.
digest, ticket = ectx.hash(b"fff", TPM2_ALG.SHA256, ESYS_TR.OWNER)

# 정책 세션을 시작합니다.
session = ectx.start_auth_session(
    tpm_key=ESYS_TR.NONE,  # TPM 키를 사용하지 않습니다.
    bind=ESYS_TR.NONE,  # 바인딩 키를 사용하지 않습니다.
    session_type=TPM2_SE.POLICY,  # 정책 모드의 세션을 생성합니다.
    symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),  # 대칭 암호화 알고리즘을 사용하지 않습니다.
    auth_hash=TPM2_ALG.SHA256,  # SHA-256 해시 알고리즘을 사용합니다.
)

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

try:
    # 정책을 실행합니다.
    with policy(polstr, TPM2_ALG.SHA256) as p:
        p.set_callback(policy_cb_types.CALC_PCR, pcr_cb)  # PCR 계산 콜백을 설정합니다.
        p.calculate()  # 정책을 계산합니다.
        cjb = p.get_calculated_json()  # 계산된 정책 JSON을 가져옵니다.
        json_object = json.loads(cjb)  # JSON을 파싱합니다.
        print("========= Policy ========")
        print(json.dumps(json_object, indent=4))  # 계산된 정책을 출력합니다.
        print("=========================")
        p.execute(ectx, session)  # 정책을 실행합니다.
except Exception as e:
    print(e)  # 예외가 발생하면 출력합니다.
    sys.exit(1)  # 프로그램을 종료합니다.

# 데이터에 서명을 생성합니다.
s = ectx.sign(childHandle, TPM2B_DIGEST(digest), scheme, validation, session1=session)

# 서명의 알고리즘, 해시 알고리즘, 서명 값을 출력합니다.
print(f"Signing Algorithm: {s.sigAlg}")
print(f"Hash Algorithm: {s.signature.rsassa.hash}")
print(f"Signature Value: {s.signature.rsassa.sig}")

# 세션과 키의 컨텍스트를 플러시합니다.
ectx.flush_context(session)
ectx.flush_context(childHandle)

#ectx.verify_signature(childHandle,  TPM2B_DIGEST(digest), signature)

# TPM API를 종료합니다.
ectx.close()