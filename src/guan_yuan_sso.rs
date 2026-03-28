// 本模块演示如何在 Rust 中实现与 Java 版本等价的 RSA SSO 工具。
// 主要步骤：Base64 解码密钥、按块加解密、以及从环境变量读取生产配置。
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use num_bigint_dig::BigUint;
#[cfg(test)]
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
#[cfg(test)]
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::{env, io, iter};

// 部署时把公钥、私钥放在环境变量里，避免把密钥写进源码。
const PUBLIC_KEY_ENV: &str = "GUANYUAN_PUBLIC_KEY";
const PRIVATE_KEY_ENV: &str = "GUANYUAN_PRIVATE_KEY";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn simple_error(msg: &str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::new(io::ErrorKind::Other, msg.to_string()))
}

// 下面两个常量与函数只在测试里启用，用随机数生成一对 RSA 密钥。
#[cfg(test)]
const KEY_SIZE: usize = 1024;

#[cfg(test)]
/// 生成一对新的 RSA 密钥，并以 Base64（DER 格式）返回。
pub fn create_keys() -> Result<(String, String)> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, KEY_SIZE)?;
    // 直接把私钥转换成对应的公钥，保持与 Java 示例一致。
    let public_key = private_key.to_public_key();
    let public_key_der = public_key.to_public_key_der()?.as_bytes().to_vec();
    let private_key_der = private_key.to_pkcs8_der()?.as_bytes().to_vec();
    Ok((
        BASE64.encode(public_key_der),
        BASE64.encode(private_key_der),
    ))
}

/// 将 Base64 字符串还原为 `RsaPublicKey`。
pub fn get_public_key(public_key: &str) -> Result<RsaPublicKey> {
    let key_bytes = BASE64.decode(public_key)?;
    Ok(RsaPublicKey::from_public_key_der(&key_bytes)?)
}

/// 将 Base64 字符串还原为 `RsaPrivateKey`。
pub fn get_private_key(private_key: &str) -> Result<RsaPrivateKey> {
    let key_bytes = BASE64.decode(private_key)?;
    Ok(RsaPrivateKey::from_pkcs8_der(&key_bytes)?)
}

/// 用私钥（通常放在服务端）对 JSON 字符串进行分块加密。
pub fn private_encrypt(data: &str, private_key: &RsaPrivateKey) -> Result<String> {
    let block_size = private_key.size();
    let mut encrypted = Vec::new();
    // RSA 不能一次处理大字符串，所以要切成 block_size-11 的小块并逐块处理。
    for chunk in data.as_bytes().chunks(block_size - 11) {
        let padded = pkcs1_pad_block(chunk, block_size)?;
        let block = mod_pow(&padded, private_key.d(), private_key.n(), block_size);
        encrypted.extend_from_slice(&block);
    }
    Ok(BASE64.encode(encrypted))
}

/// 用公钥（下发给信任方）解密密文，恢复出原始 JSON。
pub fn public_decrypt(data: &str, public_key: &RsaPublicKey) -> Result<String> {
    let decoded = BASE64.decode(data)?;
    let block_size = public_key.size();
    if decoded.len() % block_size != 0 {
        return Err(simple_error("ciphertext is not aligned to the key size"));
    }
    let mut plain = Vec::new();
    for block in decoded.chunks(block_size) {
        let decrypted = mod_pow(block, public_key.e(), public_key.n(), block_size);
        let payload = pkcs1_unpad_block(decrypted.as_slice())?;
        plain.extend_from_slice(&payload);
    }
    Ok(String::from_utf8(plain)?)
}

/// 手动实现 PKCS#1 v1.5 填充，让 Rust 行为与 Java Cipher 保持一致。
fn pkcs1_pad_block(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if data.len() > block_size - 11 {
        return Err(simple_error("chunk too large for RSA block"));
    }
    let padding_len = block_size - data.len() - 3;
    let mut block = Vec::with_capacity(block_size);
    block.push(0x00);
    block.push(0x01); // PKCS#1 要求 block type 1（私钥加密）。
    block.extend(iter::repeat_n(0xFF, padding_len));
    block.push(0x00);
    block.extend_from_slice(data);
    Ok(block)
}

/// 解出填充，还原真实明文。
fn pkcs1_unpad_block(block: &[u8]) -> Result<Vec<u8>> {
    if block.len() < 11 {
        return Err(simple_error("block too small for PKCS#1 v1.5"));
    }
    if block[0] != 0x00 || block[1] != 0x01 {
        return Err(simple_error("invalid padding header"));
    }
    let mut index = 2;
    while index < block.len() && block[index] == 0xFF {
        index += 1;
    }
    if index >= block.len() || block[index] != 0x00 {
        return Err(simple_error("invalid padding delimiter"));
    }
    Ok(block[index + 1..].to_vec())
}

/// 执行模幂运算（核心的 RSA 计算），再把结果补齐到固定长度。
fn mod_pow(block: &[u8], exponent: &BigUint, modulus: &BigUint, block_size: usize) -> Vec<u8> {
    let value = BigUint::from_bytes_be(block);
    // RSA 的核心是执行 m^d mod n 或 c^e mod n，这里用大整数库帮我们完成。
    let transformed = value.modpow(exponent, modulus);
    let mut bytes = transformed.to_bytes_be();
    if bytes.len() < block_size {
        let mut padded = vec![0; block_size - bytes.len()];
        padded.extend_from_slice(bytes.as_slice());
        bytes = padded;
    }
    bytes
}

#[allow(dead_code)]
pub fn to_hex_string(value: &str) -> String {
    // Java 版本把 Base64 结果逐字符转为十六进制字符串，这里复现同样的行为。
    value.chars().map(|ch| format!("{:x}", ch as u32)).collect()
}

#[allow(dead_code)]
pub fn run_demo() -> Result<()> {
    // run_demo 会读取环境变量里的密钥，拼出 SSO token 并打印出来。
    const URL: &str = "https://ds.cdlsym.com/m/page/ma81657b8a6404bc39b936c5?";
    let public_key = match env::var(PUBLIC_KEY_ENV) {
        Ok(value) => Some(get_public_key(value.as_str())?),
        Err(_) => {
            println!("未从环境变量 {PUBLIC_KEY_ENV} 读取到公钥，将跳过解密校验。");
            None
        }
    };
    let private_key_raw = env::var(PRIVATE_KEY_ENV)
        .map_err(|_| format!("environment variable {PRIVATE_KEY_ENV} 未设置"))?;
    let private_key = get_private_key(private_key_raw.as_str())?;

    println!("私钥加密——公钥解密");
    let timestamp = Utc::now().timestamp();
    println!("当前时间的 timestamp（到秒）: {timestamp}");

    let payload = format!(
        "{{\"domainId\":\"{domain}\",\"externalUserId\":\"{user}\",\"timestamp\":{timestamp},\"expiredTimeSeconds\":28800}}",
        domain = "guanbi",
        user = "LSYM003859",
        timestamp = timestamp
    );

    println!("\r明文：\r\n{payload}");
    let encoded = private_encrypt(&payload, &private_key)?;
    let token_hex = to_hex_string(&encoded);
    println!(
        "{URL}pref.HostNavOnly=true&pageRenderType=phoneView&provider=guanbi&ssoToken={token_hex}"
    );
    println!("{token_hex}");

    if let Some(public_key) = public_key {
        let decoded = public_decrypt(&encoded, &public_key)?;
        println!("解密后文字: {decoded}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_private_public() {
        // 测试用例：私钥加密、公钥解密后应得到原文。
        let (public, private) = create_keys().unwrap();
        let private_key = get_private_key(private.as_str()).unwrap();
        let public_key = get_public_key(public.as_str()).unwrap();
        let cipher = private_encrypt("hello world", &private_key).unwrap();
        let plain = public_decrypt(cipher.as_str(), &public_key).unwrap();
        assert_eq!(plain, "hello world");
    }
}
