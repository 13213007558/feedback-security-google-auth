# always_use_jwt_access 离线决策矩阵(google-auth 2.48.0)

基于本仓库源码 `google/oauth2/service_account.py` 与离线实验(见
`evidence_jwt_access.py`,纯内存 RSA 密钥 + 记录型 mock transport,零网络)。

## 两种 JWT 不可互换

| | 自签 JWT(直连 API) | 签名断言(OAuth 交换) |
|---|---|---|
| 生成处 | `jwt.Credentials._make_jwt`(google/auth/jwt.py:537) | `_make_authorization_grant_assertion`(service_account.py:393) |
| `aud` | API host(如 `https://pubsub.googleapis.com/`);带 scope 时**无 aud** | 硬编码 `https://oauth2.googleapis.com/token`(service_account.py:412) |
| `iss`/`sub` | 均为服务账号邮箱 | iss=服务账号邮箱;sub=委托用户(仅 DWD) |
| 用途 | 直接作为 API 请求的 bearer token | POST 到 token endpoint 换不透明 access token |
| 网络 | 无(`jwt.Credentials.refresh` 不用 request,jwt.py:563) | 每次刷新一次 POST |

两者都能验签,但 aud 与语义不同:自签 JWT 发给 token endpoint 会被拒(aud 不匹配),
断言发给 API 也一样无效。**互换不成立。**

## 决策矩阵(刷新路径)

| # | scopes | default_scopes | subject | universe | jwt_access | 路径 | 调 token endpoint? | 最终 token |
|---|--------|----------------|---------|----------|------------|------|--------------------|-----------|
| S1 | ✓ | – | – | 默认 | True | 自签 JWT | **否** | JWT:iss=sub=SA,`scope` claim,无 `aud` |
| S2 | ✓ | – | – | 默认 | False(默认) | OAuth 交换 | 是 | 不透明 access token |
| S3 | – | ✓ | – | 默认 | True | 自签 JWT | **否** | JWT,`scope` 取自 default_scopes |
| S4 | – | – | – | 默认 | True | 回退到交换 | 是 | 不透明 token(空 scope,服务端会拒) |
| S5 | ✓ | – | user@… | 默认 | 任意(被忽略) | OAuth 交换(DWD) | **必须** | 不透明 token;断言含 `sub` |
| S6 | ✓ | – | – | 非默认 | 强制 True | 自签 JWT | **否** | JWT(构造时强制开启,service_account.py:190) |
| S7 | – | – | user@… | 非默认 | – | **RefreshError** | – | 非默认 universe 不支持 DWD(service_account.py:443) |
| S8 | – | – | – | 默认 | False + transport 给 audience | 自签 JWT | 否 | JWT,`aud=https://<host>/` |
| S9 | ✓ | – | – | 默认 | True + transport 给 audience | 自签 JWT | 否 | JWT,scope 优先于 audience |

优先级(`_create_self_signed_jwt`,service_account.py:463):**scopes > audience > default_scopes**。
audience 由 transport 适配器注入(requests.py:424、grpc.py:75、urllib3.py:308,取 default_host)。

判定链(`_perform_refresh_token`,service_account.py:437):
1. `subject` 非空 → 永远走交换(`_use_self_signed_jwt` 要求 subject 为 None,service_account.py:426);
2. 非默认 universe + subject → 直接 RefreshError;
3. 否则有 `_jwt_credentials` → 本地签名;没有 → 交换。

## 实验输出(摘要)

```
S1 scopes + jwt_access=True                endpoint=False  cred-type/jwt   {iss=sub=SA, scope}
S2 scopes + jwt_access=False(默认)         endpoint=True   cred-type/sa    不透明 token;断言 aud=oauth2.../token
S3 default_scopes + jwt_access=True        endpoint=False  cred-type/jwt   {scope=default_scopes}
S4 无 scope + jwt_access=True              endpoint=True   cred-type/sa    回退交换,断言 scope=""
S5 with_subject + jwt_access=True          endpoint=True   cred-type/sa    断言含 sub=user@example.com
S6 非默认 universe + scopes                endpoint=False  cred-type/jwt   自签(标志被强制 True)
S7 非默认 universe + with_subject          RefreshError: DWD not supported
S8 无 scope + jwt_access=False + audience  endpoint=False  cred-type/jwt   {aud=https://pubsub.googleapis.com/}
S9 scopes + jwt_access=True + audience     endpoint=False  cred-type/jwt   scope 优先,无 aud
```

复现:`.venv/bin/python jwt_access_analysis/evidence_jwt_access.py`
可观测信号:请求头 `x-goog-api-client` 中 `cred-type/jwt`(自签)vs `cred-type/sa`(交换)。

## 结论:优化能用在哪里

**适合开启 `always_use_jwt_access=True`(省掉交换):**
- 普通 API 访问、显式 `scopes` 或仅有 `default_scopes`、默认 universe、无 `with_subject`
  —— 每个凭据实例每小时省一次 token endpoint 往返(S1/S3);
- 非默认 universe 本来就被强制开启,无需操作(S6)。

**必须保留交换过程(标志无效或不适用):**
- 所有 `with_subject` 域级委托:标志被忽略,sub 只能经断言传给 token endpoint(S5);
- 非默认 universe 的 DWD:直接报错,属于配置错误而非优化空间(S7);
- `IDTokenCredentials`:独立类,恒走交换,不受此标志影响;
- 完全不带 scope 的凭据:即使开了标志也回退交换(S4),应靠 transport audience(S8)。

**注意事项:**
- 带 scope 的自签 JWT 无 `aud`(AIP-4111),不要把它当作自有服务的 audience 校验 token;
- 自签路径下 scope 错误、DWD 撤销等服务端问题推迟到 API 调用时才暴露(交换路径在刷新时暴露);
- 设了 `GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED=true` 时刷新会额外触发 trust boundary 查询,与是否自签无关;
- 非默认 universe 上 `with_always_use_jwt_access(False)` 会抛 `InvalidValue`(service_account.py:324)。
