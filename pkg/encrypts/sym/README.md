# Using AES-GCM with JWE
Important points to note when decrypting JWE tokens when AES-GCM is used.

## JWE encryption
Apparent JWE libraries behaviour (without very clear documentation):

| - | JWE Section | Remarks | Content | Encoded value |
| --- | --- | --- | --- | --- |
| public key | - | To encrypt the `CEK` | - | `-----BEGIN PUBLIC KEY-----`<br/>`MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzoPzyXFz43+tEPlC/YQ0`<br/>`AlmJchEst/UY2LaOKUHBBgNoJrudtw32UZ5isoFtBcbsYAvr3JQwXKbWQZsn0y7c`<br/>`7/9NyPQx4QDcCYf927kY6089anJtouk7kRD4icLXnbCXKJy3zDGzklAtMe6ZZ841`<br/>`+KA7P7TjqI1vVXdDu3chiFA20PHJNNvXI5EfsDujG0mUUYiSSSL7cTaNxxiGvvjl`<br/>`fgJp+NaHwJpvGT8xyo8YdXXIB47qKNulQZRCXiauiF7Wlh5uROARVUUXIZOfDds6`<br/>`SsKlIywARDt+ohkgzp9KkfjRvAC/DZY6n1OcoMdPYBVtb6Xp1kcgTbQMTEENhzdZ`<br/>`dQIDAQAB`<br/>`-----END PUBLIC KEY-----` |
| additional<br/>authenticated<br/>data (AAD) | Protected<br/>Header | The `base64` encoded value is<br/>used directly | `{`<br/>&nbsp;&nbsp;`"alg": "RSA-OAEP-256",`<br/>&nbsp;&nbsp;`"enc": "A128CBC-HS256“`<br/>`}` | `eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0` |
| content<br/>encryption<br/>key | CEK | Encrypted with the `public key`,<br/>then `base64` encoded | Auto-generated | `TzTXwb_w-m2gF03ZYBKP1jbMHRYBl2NufLNDnMlIV1_uxXTTUMfJJr4CwOOkCVPYra0Ko_0kCkk`<br/>`SmHSFxfm4hXE0eWdikyqnkaNaey57tE05mrhm2ri-DH-5KV1yeIbZ3GFwaWm2Fy46YyXASgbrfC`<br/>`fwMpw5RNb3kadyMWxSnbmZGsVnJr1f1aB0_Qaw0gpujvcxsA3ynPCwKt175JNYSOff6RzxJ0mJE`<br/>`RJhYrel_Ysfjlz8nPNXs-BaISLSpLdLHVJkrjFY5fU65FJ6GXkbdbADutXwd1KPRg6VfLUBzwaR`<br/>`hy1swFJsdKkO5pPcyDctjMXGirxVmAiYPPk8Bc6J6A` |
| initialization<br/>vector | IV | `base64` encoded, not concat<br/>with `Ciphertext` | Auto-generated | `-xgKzD_lztAYBMv64B-Xvw` |
| payload | Ciphertext | Encrypted with the `CEK`,<br/>then `base64` encoded | `JWS HEADER: {`<br/>&nbsp;&nbsp;`"typ": "JWT",`<br/>&nbsp;&nbsp;`"alg": "RS256“`<br/>`}`<br/>`JWS PAYLOAD: {`<br/>&nbsp;&nbsp;`"jti": "2975dd35-6baa-47bc-9c29-be547b0b4cf8",`<br/>&nbsp;&nbsp;`"iat": 1742961808,`<br/>&nbsp;&nbsp;`"aud": "JWTest",`<br/>&nbsp;&nbsp;`"issueTime": "2025-03-26T12:03:28.339",`<br/>&nbsp;&nbsp;`"issuer": "CDI-PUSH-001",`<br/>&nbsp;&nbsp;`"Payload": {`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`"type": "Consent",`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`"id": "37ce697c-83cd-4e67-8e78-2cc00b76cbe2",`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`"status": "ConsentSubmitted",`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`"updateTime": {`<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`"t": 1742961808,`<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`"humanT": "2025-03-26 12:03:28“`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`}`<br/>&nbsp;&nbsp;`}`<br/>`}` | `1m-Oke7vqP-E2WNAmIYmUxYHC1TNf_H2OVKzwtLsxtAKmSlwIxLu3-JI4qqAp1Ra`<br/>`4nKG4eEexSQFop4l9vI9tgZLWuHZJOSLbt2AS0G-mwFDbA_QYuduybEMdLBKPS9K`<br/>`js3CuvFMC78AIMRriJF79ncqnMT3iOyq2CHiZ0VIuPAkmY_cr3g327jM1VLdtEG2`<br/>`5hBjA7lOr9hnKrjUnHocEQYleR2S3pX6Ctr31RjGoMVT5ZMT8sAV9ZlQO9sm3fMK`<br/>`pLHL7-Z9KK45RSt1sT7Q1it8YSI_24axYH4pbMvLDE5bCVguQ5pSZULdZs-K7E7i`<br/>`j7Qhi0Cgze8yZjxE31dzAcEPnVp1cfyMNGCeDt176rH3RH7HepGTXrZgO3euBD4V`<br/>`7TgKvkB74g7HPlMJJWJw0WlLEaNOShsr2ZMDH1uXsVi2_a_GzwZ7lwEdyV9vr9uK`<br/>`uO6zOxzRpFVF0IFs2XWgodQkUqhdkDaWDiisEpxx0hMuBpA2vKq7RrvafwhVLubc`<br/>`LyYU9IJSWa14GndE1o55MIzjk1uNL8MI8XvvEnFktBFN4X7ndkDY2Kdm4e04g-V8`<br/>`MQfgzGm2XMZ4crYyoj3OY4P1Fw3qDBTs5ir5feAN7COPMnm55QgJq7h00e19ovvG`<br/>`tPJWRNszvwoGDyjxpxXSQU7B3dlMGTLNyLkXxA-FitlOhLe78SrC48SVxolWY13e`<br/>`Ktaz6h_whzc3gaY-5HJXlKttpjUfL59PTushRyssz_SLvXfs-3azC0rZc2ptpiY-`<br/>`J6AAnGZaaVzf6EBPjz-XTBAD2oY1Ac7Hod2EDYQNUrQ0K0mP_yWCJE82aC1-LOlZ`<br/>`HmKXgdw_8fUmhmNxN-s3fZQJzUI8NYxt3zcomAytinhf7R5IjL587_WdmFjZM31W`<br/>`aizvqh8XfVETqsrWYVwIsCtd7pUspjU7fo61Pm3GQb4pTDZK4rEAKY_WCvIFzSve`<br/>`4m6amBCvY2ePk1ov70j_rtbKnOAwh_G3-8l3eaQsWSILw3DVW11eRBIIXINSaoNA`<br/>`OPvWfyyhT-nbaxjcqE06FA` |
| authentication<br/>tag | Tag | `base64` encoded, not concat<br/>with `Ciphertext` | Auto-generated | `SvVoFiwuQXySMug6zl2Xhg` |

## JWE decryption
| - | JWE Section | Remarks | Content | Encoded value |
| --- | --- | --- | --- | --- |
| private key | - | To decrypt the `CEK` | - | `-----BEGIN PRIVATE KEY-----`<br/>`MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDOg/PJcXPjf60Q`<br/>`...`<br/>`ShdGOcvcNVGL1uaNFtfw1iq4WBuGbg4oADF2Yg6iRDJMub7jbkxxyxsyUXeqDQLA`<br/>`w5tOxhcEKg/N4gk7jlv39g==`<br/>`-----END PRIVATE KEY-----` |
| additional<br/>authenticated<br/>data (AAD) | Protected<br/>Header | The `base64` encoded value is<br/>used directly | `{`<br/>&nbsp;&nbsp;`"alg": "RSA-OAEP-256",`<br/>&nbsp;&nbsp;`"enc": "A128CBC-HS256“`<br/>`}` | `eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0` |
| content<br/>encryption<br/>key | CEK | `base64` decoded | Decrypted with the `private key` | `TzTXwb_w-m2gF03ZYBKP1jbMHRYBl2NufLNDnMlIV1_uxXTTUMfJJr4CwOOkCVPYra0Ko_0kCkk`<br/>`SmHSFxfm4hXE0eWdikyqnkaNaey57tE05mrhm2ri-DH-5KV1yeIbZ3GFwaWm2Fy46YyXASgbrfC`<br/>`fwMpw5RNb3kadyMWxSnbmZGsVnJr1f1aB0_Qaw0gpujvcxsA3ynPCwKt175JNYSOff6RzxJ0mJE`<br/>`RJhYrel_Ysfjlz8nPNXs-BaISLSpLdLHVJkrjFY5fU65FJ6GXkbdbADutXwd1KPRg6VfLUBzwaR`<br/>`hy1swFJsdKkO5pPcyDctjMXGirxVmAiYPPk8Bc6J6A` |
| initialization<br/>vector | IV | `base64` decoded | Not contained in `Ciphertext` | `-xgKzD_lztAYBMv64B-Xvw` |
| payload | Ciphertext | `base64` decoded, appended with<br/>the `base64` decoded `Tag`,<br/>then decrypted with the `CEK` | `JWS HEADER: {`<br/>&nbsp;&nbsp;`"typ": "JWT",`<br/>&nbsp;&nbsp;`"alg": "RS256“`<br/>`}`<br/>`JWS PAYLOAD: {`<br/>&nbsp;&nbsp;`"jti": "2975dd35-6baa-47bc-9c29-be547b0b4cf8",`<br/>&nbsp;&nbsp;`"iat": 1742961808,`<br/>&nbsp;&nbsp;`"aud": "JWTest",`<br/>&nbsp;&nbsp;`"issueTime": "2025-03-26T12:03:28.339",`<br/>&nbsp;&nbsp;`"issuer": "CDI-PUSH-001",`<br/>&nbsp;&nbsp;`"Payload": {`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`"type": "Consent",`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`"id": "37ce697c-83cd-4e67-8e78-2cc00b76cbe2",`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`"status": "ConsentSubmitted",`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`"updateTime": {`<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`"t": 1742961808,`<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`"humanT": "2025-03-26 12:03:28“`<br/>&nbsp;&nbsp;&nbsp;&nbsp;`}`<br/>&nbsp;&nbsp;`}`<br/>`}` | `1m-Oke7vqP-E2WNAmIYmUxYHC1TNf_H2OVKzwtLsxtAKmSlwIxLu3-JI4qqAp1Ra`<br/>`4nKG4eEexSQFop4l9vI9tgZLWuHZJOSLbt2AS0G-mwFDbA_QYuduybEMdLBKPS9K`<br/>`js3CuvFMC78AIMRriJF79ncqnMT3iOyq2CHiZ0VIuPAkmY_cr3g327jM1VLdtEG2`<br/>`5hBjA7lOr9hnKrjUnHocEQYleR2S3pX6Ctr31RjGoMVT5ZMT8sAV9ZlQO9sm3fMK`<br/>`pLHL7-Z9KK45RSt1sT7Q1it8YSI_24axYH4pbMvLDE5bCVguQ5pSZULdZs-K7E7i`<br/>`j7Qhi0Cgze8yZjxE31dzAcEPnVp1cfyMNGCeDt176rH3RH7HepGTXrZgO3euBD4V`<br/>`7TgKvkB74g7HPlMJJWJw0WlLEaNOShsr2ZMDH1uXsVi2_a_GzwZ7lwEdyV9vr9uK`<br/>`uO6zOxzRpFVF0IFs2XWgodQkUqhdkDaWDiisEpxx0hMuBpA2vKq7RrvafwhVLubc`<br/>`LyYU9IJSWa14GndE1o55MIzjk1uNL8MI8XvvEnFktBFN4X7ndkDY2Kdm4e04g-V8`<br/>`MQfgzGm2XMZ4crYyoj3OY4P1Fw3qDBTs5ir5feAN7COPMnm55QgJq7h00e19ovvG`<br/>`tPJWRNszvwoGDyjxpxXSQU7B3dlMGTLNyLkXxA-FitlOhLe78SrC48SVxolWY13e`<br/>`Ktaz6h_whzc3gaY-5HJXlKttpjUfL59PTushRyssz_SLvXfs-3azC0rZc2ptpiY-`<br/>`J6AAnGZaaVzf6EBPjz-XTBAD2oY1Ac7Hod2EDYQNUrQ0K0mP_yWCJE82aC1-LOlZ`<br/>`HmKXgdw_8fUmhmNxN-s3fZQJzUI8NYxt3zcomAytinhf7R5IjL587_WdmFjZM31W`<br/>`aizvqh8XfVETqsrWYVwIsCtd7pUspjU7fo61Pm3GQb4pTDZK4rEAKY_WCvIFzSve`<br/>`4m6amBCvY2ePk1ov70j_rtbKnOAwh_G3-8l3eaQsWSILw3DVW11eRBIIXINSaoNA`<br/>`OPvWfyyhT-nbaxjcqE06FA` |
| authentication<br/>tag | Tag | `base64` decoded, append to the<br/>`base64` decoded `Ciphertext`<br/>before decryption | Not contained in `Ciphertext` | `SvVoFiwuQXySMug6zl2Xhg` |

## Example
```bash
> c9ryptool decrypt -a RSA-2048-OAEP-SHA256 \
>   -k private.key \
>   -i cek.jwe --encode-in=rawbase64url \
>   -o cek.hex --encode-out=hex
>
> c9ryptool decrypt -a AES-256-GCM \
>   -k cek.hex     --encode-key=hex \
>   -i payload.jwe --encode-in=rawbase64url \
>   --iv=iv.jwe    --encode-iv=rawbase64url \
>   --tag=tag.jwe  --encode-tag=rawbase64url \
>   --aad=aad.jwe \
>   -o token.jws
```
