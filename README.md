# Python ESAPI 및 FAPI 예제
출처:
* [https://github.com/salrashid123/tpm2/blob/master/pytss/README.md](https://github.com/salrashid123/tpm2/blob/master/pytss/README.md)


## 설치

```bash
apt-get install libtss2-dev
python3 -m pip install tpm2-pytss
```


## ESAPI

- `esapi_create_sign.py`: RSA 키 생성 및 서명/검증
- `esapi_encrypt_decrypt.py`: AES 키 생성 및 암호화/복호화
- `esapi_hmac_import.py`: HMAC 키 가져오기 및 사용
- `esapi_keyfile.py`: PEM 형식의 키 파일 생성 및 사용
- `esapi_auth.py`: 인증 비밀번호로 키 생성
- `esapi_pcr.py`: PCR 정책으로 키 생성
- `esapi_session_encryption_auth.py`: 비밀번호 AES로 암호화된 세션
- `esapi_session_encryption_pcr.py`: PCR 정책으로 AES 암호화된 세션
- `esapi_session_encryption_authvalue_pcr_aes.py`: PCR 및 인증값으로 AES 암호화된 세션
- `esapi_session_encryption_authvalue_pcr_rsa.py`: PCR 및 인증값으로 RSA 암호화된 세션
- `esapi_tpm2.py`: tpm2_tools로 생성된 키 로드
- `fapi_create_sign.py`: RSA 키 생성 및 서명/검증
- `fapi_seal_unseal.py`: 봉인/해제
- `fapi_import_tpm2.py`: tpm2tools로 생성된 공개/개인 키를 FAPI 컨텍스트로 가져오기
- `fapi_export_tpm2.py`: FAPI 컨텍스트에서 tpm2tools로 읽을 수 있는 공개/개인 키 블롭으로 내보내기
- `fapi_auth.py`: 비밀번호 인증으로 키 생성 및 바인딩
- `fapi_pcr.py`: PCR 정책으로 키 생성 및 바인딩


## 정책 JSON

[JSON 데이터 유형 및 정책 언어 사양](https://trustedcomputinggroup.org/resource/tcg-tss-json/)

## ESAPI 세션 암호화

출처: [TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_8May23-3.pdf)

```
• 응용 프로그램 개발자는 일반적으로 고수준 TCG Feature API (FAPI)를 사용합니다. FAPI의 호환되는 TSS 구현은 명령어와 응답을 자동으로 암호화하며, 응용 프로그램 개발자가 별도의 작업을 할 필요가 없습니다.
```

```bash
rm -rf ~/.local/share/tpm2-tss/
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert 
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear  --log level=5

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

<div style="text-align: center">⁂</div>

참고 자료:

* [https://tpm2-pytss.readthedocs.io/en/latest/api.html](https://tpm2-pytss.readthedocs.io/en/latest/api.html)
* [/P_RSA2048SHA256.json](https://github.com/tpm2-software/tpm2-tss/blob/master/dist/fapi-profiles/P_RSA2048SHA256.json)
* [fapi-config](https://github.com/tpm2-software/tpm2-tss/blob/master/doc/fapi-config.md)
* [TSS_FAPI_v0p94_r09_pub.pdf](https://trustedcomputinggroup.org/wp-content/uploads/TSS_FAPI_v0p94_r09_pub.pdf)
* [TSS_JSON_Policy_v0p7_r08_pub](https://trustedcomputinggroup.org/wp-content/uploads/TSS_JSON_Policy_v0p7_r08_pub.pdf)


[^1]: https://tpm2-pytss.readthedocs.io/en/latest/api.html

[^2]: https://github.com/tpm2-software/tpm2-tss/blob/master/