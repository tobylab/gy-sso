# Hello SSO 服务

小型 Axum HTTP 服务，用于按照关元（Guan Yuan）SSO 协议签发 RSA 加密的 token。项目分成可复用的库模块与极薄的启动二进制，方便后续拓展。

## 模块结构

| 模块 | 说明 |
| --- | --- |
| `src/lib.rs` | 暴露 `guan_yuan_sso` 与 `http_api` 两个库模块。 |
| `src/guan_yuan_sso.rs` | Base64/RSA 工具：加载 PKCS#8 密钥、按块加/解密、十六进制编码等。 |
| `src/http_api.rs` | Axum AppState、路由与 handler（`/health`、`/api/token`）。 |
| `src/main.rs` | 只负责读取环境变量、初始化 tracing，并托管 `axum::serve`。 |

## 环境变量

| 变量 | 作用 | 默认值 |
| --- | --- | --- |
| `GUANYUAN_PRIVATE_KEY` | **必填**，Base64 编码的 PKCS#8 私钥，用于加密 token。 | 无 |
| `GUANYUAN_PUBLIC_KEY` | 可选，若提供可在 demo/测试中验证解密。 | 无 |
| `SSO_BASE_URL` | SSO 页面基础 URL，末尾自动补 `?`/`&`。 | `https://ds.cdlsym.com/m/page/ma81657b8a6404bc39b936c5?` |
| `SSO_PROVIDER` | 默认的 provider 名称，可被请求体覆盖。 | `guanbi` |
| `SSO_BIND_ADDR` | 监听地址（`IP:PORT`）。 | `0.0.0.0:8080` |

## 开发命令

- `cargo fmt` – 按 rustfmt 统一风格。
- `cargo clippy -- -D warnings` – 静态检查并禁止告警。
- `cargo test` – 运行 RSA 与 HTTP handler 的单元测试。
- `cargo run` – 在 `SSO_BIND_ADDR` 启动服务；需提前导出私钥变量。

## 运行示例

```bash
export GUANYUAN_PRIVATE_KEY="$(cat private_key.b64)"
export SSO_BIND_ADDR="127.0.0.1:8080"
cargo run
```

启动后日志显示 `Listening on http://127.0.0.1:8080`。

## HTTP API

### `GET /health`

返回 `{"status":"ok"}`，可用于探活。

### `POST /api/token`

请求体（驼峰 JSON）：

```json
{
  "domainId": "guanbi",
  "externalUserId": "tester",
  "expiredTimeSeconds": 28800,
  "provider": "guanbi" // 可选
}
```

响应体：

```json
{
  "tokenHex": "<Base64 token 的十六进制表示>",
  "tokenBase64": "<Base64 token>",
  "timestamp": 1719880000,
  "ssoUrl": "https://...&provider=guanbi&ssoToken=<tokenHex>"
}
```

错误时返回 `{"error": "<原因>"}`，并配合 `400`（校验失败）或 `500`。

## 相关实现细节

- `AppState` 持有 `Arc<RsaPrivateKey>`，避免每个请求重新解析私钥。
- `guan_yuan_sso::private_encrypt` 采用 PKCS#1 v1.5 padding，并支持分块，确保与 Java 版兼容。
- `TokenRequest` 的 `expiredTimeSeconds` 默认 28,800 秒，可通过请求体修改。
- `SSO_BASE_URL` 会自动补出末尾的 `?` 或 `&`，拼装 token URL 更稳健。

如需 CLI 或其他进程生成 token，可直接复用 `guan_yuan_sso` 模块，无需依赖 HTTP 层。
