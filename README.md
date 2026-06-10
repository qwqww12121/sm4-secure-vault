# 基于国密 SM4 与口令派生机制的本地保密文件库

## 作品简介

本项目是《密码学导论》课程大作业的软件设计作品，实现了一个本地命令行保密文件库。系统使用自实现 SM4 分组密码算法，对文件内容采用 SM4-CBC + PKCS#7 填充加密，并使用 HMAC-SHA256 做 Encrypt-then-MAC 认证；用户主口令通过 PBKDF2-HMAC-SHA256 派生出加密密钥和认证密钥；文件索引也以加密形式保存，避免明文泄露文件名、大小、导入时间等元信息。本项目最初目标是使用 SM4 文件加密实现课程要求。后续我加入了加密索引、对象 HMAC 认证、诱骗视图和 CBC 轮密钥复用优化，使它更像一个完整的本地保密文件库。

核心密码算法 SM4 为项目内纯 Python 实现，未调用 pycryptodome、cryptography、gmssl 等现成密码算法库。CBC 模式在单次文件加解密过程中会先展开一次 32 轮轮密钥，再对所有分组复用该轮密钥，避免每个 16 字节分组重复执行 key schedule。

> 选型说明：SM4 工作模式选择了 CBC 而非 GCM。虽然 GCM 自带认证加密不需要额外 HMAC，但 SM4-GCM 的 GHASH 乘法在纯 Python 中实现复杂度较高，且本课程重点在于分组密码自身原理的理解。CBC + 独立 HMAC 的 Encrypt-then-MAC 结构在概念上更直观，便于分步验证 SM4 加解密正确性和 MAC 完整性校验的正确性。

## 功能列表

- 初始化本地文件库。
- 导入文件并加密保存。
- 对加密文件对象执行 HMAC-SHA256 完整性认证，篡改后拒绝解密。
- CBC 模式复用 SM4 轮密钥，减少大文件加解密时的重复密钥扩展开销。
- 解密索引并查看文件列表。
- 按文件名导出并解密文件。
- 删除文件库中的加密文件对象。
- 支持诱骗视图：错误口令或备用诱骗口令可以浏览假文件列表，并导出有意义的欺骗性明文。
- 使用单元测试验证 SM4、填充、KDF、文件库流程和诱骗视图。
- 运行 benchmark 统计不同大小文件的加解密时间和吞吐率。

## 项目结构

```text
sm4-secure-vault/
├── README.md
├── requirements.txt
├── src/
│   ├── main.py
│   ├── vault_core.py
│   ├── config.py
│   ├── exceptions.py
│   ├── crypto/
│   ├── storage/
│   └── utils/
├── tests/
├── benchmarks/
├── vault_data/
├── examples/
└── report/
```

运行时生成的 `vault_data/vault.meta`、`vault_data/index.enc` 和 `vault_data/objects/*.enc` 不应提交到仓库。

## 安装方式

项目核心功能只依赖 Python 标准库，建议使用 Python 3.10+。

```powershell
cd /d D:\密码学导论大作业\sm4-secure-vault
python --version
```

如果需要绘制 benchmark 图片，可以自行安装 matplotlib：

```powershell
python -m pip install matplotlib
```

## 运行方式

```powershell
python src/main.py init
python src/main.py add examples/sample.txt
python src/main.py list
python src/main.py extract sample.txt --out examples
python src/main.py remove sample.txt
python src/main.py benchmark
```

所有涉及文件库口令的命令都会通过 `getpass.getpass` 输入口令，终端不会显示口令明文。`init` 会要求重复输入一次主口令进行确认。如需配置一个可主动交出的备用诱骗口令，可使用：

```powershell
python src/main.py init --with-decoy
```

真实主口令会进入真实文件库；备用诱骗口令或其他错误口令会进入诱骗视图，看到的是假文件列表和假明文，不会访问真实密文对象。
诱骗口令下执行 `add/remove` 是诱骗视图内的模拟操作，动态诱骗记录保存在 `vault_data/decoy_index.json`，不会修改真实 `index.enc` 和真实密文对象。

## 命令行示例

```powershell
python src/main.py init
python src/main.py add examples/sample.txt
python src/main.py list
python src/main.py extract sample.txt --out examples
python src/main.py remove sample.txt
```

诱骗视图演示：

```powershell
python src/main.py list
python src/main.py extract 课程资料整理.txt --out output_decoy
```

上述两条命令输入错误口令或备用诱骗口令时，会显示诱骗文件列表，并导出有意义但不真实的明文。
如果用诱骗口令执行 `extract sample.txt --out output_decoy`，即使 `sample.txt` 不在诱骗列表中，程序也会导出一份针对 `sample.txt` 生成的诱骗明文，而不是真实文件内容。这样可以避免非法用户通过“文件不存在”判断自己处在诱骗视图中。

`list` 输出示例：

```text
Filename   | Size   | Imported At
-----------+--------+--------------------
sample.txt | 182 B  | 2026-06-08 22:00:00
```

## 测试方式

本项目使用 `unittest`，也可以由 pytest 自动发现并运行。

```powershell
python -m unittest discover tests
```

若本机安装了 pytest，也可运行：

```powershell
python -m pytest
```

测试覆盖：

- SM4 标准测试向量。
- PKCS#7 填充与非法填充。
- PBKDF2 派生结果和口令 verifier。
- 初始化、导入、列表、导出、删除完整流程。
- 错误口令和备用诱骗口令进入诱骗视图，不会泄露真实文件列表或真实明文。

## Benchmark 方式

```powershell
python benchmarks/benchmark_encrypt.py
```

脚本会自动生成 1KB、10KB、100KB、1MB、10MB 随机测试文件，并输出：

- `benchmarks/benchmark_result.csv`
- `report/tables/benchmark_result.csv`

如需绘图：

```powershell
python benchmarks/plot_benchmark.py
```

matplotlib 可用时会在 `report/figures/` 下生成加密时间、解密时间和吞吐率曲线图；不可用时会给出提示，不影响核心功能。

## 安全设计说明

- SM4 密钥长度为 128 bit，分组长度为 128 bit。
- 文件内容使用 SM4-CBC 加密，每个文件使用独立随机 IV。
  - 选择 PKCS#7 而非 ISO 10126 或 zero padding 的原因：PKCS#7 是 TLS 等协议中广泛使用的填充标准，且去填充时有严格格式校验，任何填充错误都会触发异常，有助于早期发现数据损坏或篡改。
- 文件密钥策略：同一文件库内所有真实文件共用由主口令和 salt 派生出的 `enc_key` 与 `auth_key`，每个文件单独生成随机 IV 和随机对象 ID。该方案简化本地单用户文件库的密钥管理，但如果主口令被破解，整个文件库都会失守；这是统一文件库密钥策略的主要安全边界。
- 文件对象使用 Encrypt-then-MAC 结构保存：先 SM4-CBC 加密，再计算 `HMAC-SHA256(auth_key, filename || iv || ciphertext)`，提取时先验 MAC 再解密。
  - 选用 Encrypt-then-MAC 而非 MAC-then-Encrypt 或 Encrypt-and-MAC：前者在密码学上被证明是最安全的组合方式（先验 MAC 可以避免解密 oracle 攻击，密文和关联数据被完整保护）。
- 明文文件名、大小、导入时间等索引信息不直接落盘，索引先 JSON 序列化，再加密保存。
- `vault.meta` 只保存 KDF 参数、salt 和 password verifier，不保存明文口令、SM4 密钥或 HMAC 密钥。
- 主口令经 PBKDF2-HMAC-SHA256 派生 48 字节密钥材料：前 16 字节为 SM4 加密密钥，后 32 字节为 HMAC-SHA256 认证密钥。
  - 迭代次数设为 100000 次。考虑到纯 Python SM4 性能，在本地单用户场景下 100000 次是安全性与可用性的折中。轮密钥复用优化后，当前 benchmark 中 1MB 文件解密约 2.99 秒，10MB 文件解密约 29.30 秒；若进一步大幅提高 PBKDF2 迭代次数，每次命令的口令验证成本也会随之上升。
- `index.enc` 使用 `HMAC-SHA256(auth_key, iv + ciphertext)` 做完整性校验，读取时先验证 MAC，再解密。
- HMAC 比较使用 `hmac.compare_digest`。
- 系统内部会先判断口令是否能通过真实 password verifier。真实口令进入真实文件库；非真实口令不读取真实索引，而进入诱骗视图。
- 诱骗视图由 `storage/decoy_manager.py` 提供假文件记录和有意义的欺骗性明文，用于避免非法用户通过“直接报错”判断口令错误。
- 诱骗模式下的 `add/remove` 只维护 `vault_data/decoy_index.json` 中的诱骗记录，不会修改真实 `index.enc` 或真实密文对象。
- 运行时会对 `vault.meta`、`index.enc` 和密文对象尝试设置 owner-only 文件权限；该行为在 POSIX 文件系统上更可靠，在 Windows 上属于 best-effort。
- 删除密文对象时会先用零字节覆盖再删除。该策略可减少普通磁盘残留，但不承诺对 SSD、日志文件系统或备份副本实现严格安全擦除。
- PBKDF2 的中间密钥材料使用可变缓冲区并在派生后覆盖；Python 无法保证返回的不可变 `bytes` 密钥不会留在解释器内存中，因此不宣称具备完整内存密钥保护。

## 可引用技术指标

| 指标 | 取值 |
| --- | --- |
| 分组密码 | SM4 |
| 工作模式 | CBC |
| 分组长度 | 16 bytes / 128 bit |
| 密钥长度 | 16 bytes / 128 bit |
| 填充方式 | PKCS#7 |
| 文件密钥策略 | 同一文件库共用 `enc_key` / `auth_key`，每个文件独立随机 IV |
| KDF | PBKDF2-HMAC-SHA256 |
| KDF 迭代次数 | 100000 |
| 文件对象认证 | HMAC-SHA256, Encrypt-then-MAC |
| 索引认证 | HMAC-SHA256, Encrypt-then-MAC |
| 随机 IV | 每个文件独立 16 bytes IV |
| 诱骗视图 | 错误口令/备用诱骗口令返回假列表和假明文 |





