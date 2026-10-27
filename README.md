# pyprotect

Python 代码保护与授权工具集 — Cython 编译 / NaCl 加密 / Ed25519 License 三合一。

## 安装

```bash
pip install pyprotectx

# 需要 Cython 编译功能：
pip install pyprotectx[compile]
```

客户侧运行时包 `pyprotectx-protected`：PyPI 版只带占位符密钥，需厂商注入密钥后自行分发，见[运行时包与厂商定制](#运行时包-pyprotectx-protected-与厂商定制)。

## 同类工具对比

| 特性 | **pyprotect** | PyArmor | pyconcrete | SOURCEdefender |
|------|------|------|------|------|
| 保护方式 | Cython 编译 → 机器码（.so）；NaCl 加密兜底（.enc） | 字节码混淆（v8+ 已有公开解密工具）；BCC 函数→C（暂无公开解密工具） | AES-128 加密，密钥嵌 C 扩展 | AES-256 加密，密钥由官方服务管理 |
| 授权能力 | Ed25519 签名 + 机器绑定，全离线 | 机器绑定 + 过期（付费档） | 无 | 过期（SaaS 托管） |
| 成熟度 | 开源项目 | 10 年+，广泛生产使用 | 10 年，活跃维护 | 商业订阅运营 |
| 构建要求 | 需 C 编译器，.so 按平台分别构建 | 无需编译器，产物跨平台 | 需自行编译安装（无预编译包） | 无需编译器 |
| 费用 | MIT | 免费档限评估/非商用，商业需买断（Basic/Pro/Group，CI 按年） | Apache-2.0 完全免费 | 试用档产物 24h 过期；正式 £15/月/开发机 起 |

**pyprotect 的差异化定位：**

- 唯一「代码保护 + 离线机器绑定授权」双全且免费开源（MIT）的方案：授权只嵌公钥（Ed25519），无 SaaS、无订阅、无付费墙
- Cython 机器码免疫字节码级公开解密工具；每个项目构建时生成随机 NaCl 密钥
- 预编译 wheel 开箱即用（对比 pyconcrete 需自行编译安装）

> 共同短板：三类方案（含本工具）的加密强度都取决于「密钥从二进制中被提取的难度」，没有绝对安全——选型应基于威胁模型而非营销词。

---

## 使用方式

### 1. License 授权

#### 1.1 生成密钥对（一次性）

```bash
pyprotect license init -o keys/
# → keys/license_ed25519.key  (私钥，妥善保管)
# → keys/license_ed25519.pub  (公钥，随产品发布)
```

#### 1.2 为客户生成授权文件

```bash
pyprotect license generate \
  --machine-id <客户机器ID> \
  --expire-days 365 \
  --private-key keys/license_ed25519.key \
  -o license.lic
```

客户在目标机器上获取 machine-id：

```bash
# Linux
cat /etc/machine-id

# macOS
ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID
```

#### 1.3 （可选）本地验证授权文件

```bash
pyprotect license verify \
  --license-file license.lic \
  --machine-id <机器ID> \
  --public-key keys/license_ed25519.pub
```

### 2. 项目初始化

在需要保护的 Python 项目根目录执行：

```bash
pyprotect init . --packages myapp --packages lib --packages utils --keep-plain main.py
```

会在项目根目录生成 `pyprotect.yaml` 并复制 `_bootstrap.py` 和 `license_verify.py` 模板。

#### `pyprotect.yaml` 配置说明

```yaml
packages:             # 要保护的包目录（相对于项目根）
  - myapp
  - lib
keep_plain:           # 保留为明文 .py 的文件（适用场景见下文 keep_plain 说明）
  - main.py
ed25519_public_key: keys/license_ed25519.pub   # 公钥路径
```

#### keep_plain：哪些文件不适合编译

`keep_plain` 是排除清单——列出的 `.py` **既不编译也不加密，保留明文**。它只对 `packages` 内的文件生效（项目根目录的文件本就不参与保护）。典型场景：

1. **程序入口**：`python x.py` 直接运行的文件不能是 `.so`——编译产物是可导入模块，无法直接执行。入口放项目根目录天然安全；入口在包内（如 `python -m myapp.cli` 对应的 `myapp/cli.py`）时必须 keep_plain。
2. **依赖动态特性的代码**：读取自身源码的内省（如 `inspect.getsource`）、`exec`/`eval` 拼接自身路径、硬编码 `.py` 后缀的 `__file__` 路径运算等，编译后行为会改变。
3. **需要用户可见/可改的内容**：配置默认值、常量表等。

说明：Cython 编译失败的文件会自动降级为 NaCl 加密（`.enc`），因此 keep_plain 只该留给「确实既不能编译也不能加密」的文件。注意：**明文 = 零保护**，敏感逻辑不要放进 keep_plain。

### 3. 构建保护

```bash
pyprotect build . --pub-key keys/license_ed25519.pub
```

构建流程：

```
[1/5] 注入 Ed25519 公钥 → license_verify.py
[2/5] 生成随机 NaCl 密钥 → _bootstrap.py
[3/5] Cython 编译 _bootstrap.py → _bootstrap.so
[4/5] 批量 Cython 编译所有 .py → .so（编译失败则 NaCl 加密 → .enc）
[5/5] 清理 .py/.pyc/.c 源文件
```

输出：项目只剩 `.so`/`.enc` + 显式保留的 `.py` 文件。

#### 关键选项

| 选项 | 说明 |
|------|------|
| `--skip-cython` | 跳过 Cython，全部走 NaCl 加密 |
| `--no-license` | 不注入 License 公钥（纯代码混淆） |
| `--pub-key <path>` | 覆盖 yaml 中的公钥路径 |
| `--nacl-key <hex>` | 指定 64 位十六进制 NaCl 密钥（默认随机）。若客户侧用打过补丁的运行时包解密 `.enc`，需与 `runtime-patch` 传同一把密钥 |
| `--packages` / `--keep-plain` | 覆盖 yaml 配置（多值需重复 flag：`-p a -p b`） |

### 4. 目标项目接入

在项目入口 `main.py` 中：

```python
import sys

import _bootstrap                    # 必须最先导入，注册 .enc 导入钩子
from license_verify import verify_license

if not verify_license():
    print("License 无效或已过期，请联系供应商")
    sys.exit(1)

# 正常启动...
from myapp import App
App().run()
```

客户部署时需设置环境变量：

```bash
export LICENSE_FILE=/path/to/license.lic
export LICENSE_MACHINE_ID=<机器ID>
```

### 5. 授权校验行为（fail-closed）

`verify_license()` 默认失败即拒绝：未设置 `LICENSE_FILE`、文件不存在、签名无效、机器不匹配、已过期 → 一律 `valid=False`（建议业务直接退出）；授权有效且未过期才放行。

开发调试需跳过授权时，必须显式设置：

```bash
export PYPROTECT_ALLOW_DEV=1   # 仅限开发环境，受保护产品请勿携带
```

> `pyprotect license verify` 校验失败时以 exit code 1 退出，便于脚本化判断。

### 6. Docker 构建集成

```dockerfile
FROM python:3.12-slim AS build
RUN pip install pyprotectx[compile]
COPY . /project
WORKDIR /project
RUN pyprotect build . --pub-key keys/license_ed25519.pub

FROM python:3.12-slim AS runtime
COPY --from=build /project /app
# 受保护代码运行只需 pynacl：.so 内的导入钩子自带密钥，无需运行时包
RUN pip install pynacl
CMD ["python", "/app/main.py"]
```

---

## 加密原理

| 层 | 技术 | 说明 |
|----|------|------|
| Cython 编译 | `.py` → `.c` → `.so` | 原生机器码，反编译几乎不可能 |
| NaCl 加密 | XSalsa20-Poly1305 | 编译失败的文件走加密兜底 |
| 运行时解密 | `_bootstrap.so` 导入钩子 | `sys.meta_path` 拦截 `import`，自动解密 `.enc` |
| License 签名 | Ed25519 | 公钥嵌入 `.so`，私钥不留存 |

Nonce 策略：每次加密生成随机 24 字节 nonce，拼在密文头部。

---

## 完整示例

```bash
# 1. 生成密钥对
pyprotect license init -o keys/

# 2. 获取当前机器 ID，生成 License
MACHINE=$(cat /etc/machine-id)   # Linux；macOS 用 ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID
pyprotect license generate --machine-id $MACHINE --expire-days 365 \
  --private-key keys/license_ed25519.key -o license.lic

# 3. 初始化并构建
pyprotect init . --packages myapp --keep-plain main.py
pyprotect build . --pub-key keys/license_ed25519.pub

# 4. 验证运行
LICENSE_FILE=license.lic LICENSE_MACHINE_ID=$MACHINE python main.py
```

---

## 运行时包 `pyprotectx-protected` 与厂商定制

PyPI 上的运行时包只带**占位符密钥**（开箱无法解密 `.enc`、无法校验真实授权），是留给厂商二次加工的"空白模板"。

### 厂商工作流（runtime-patch）

```bash
# 1. 固定一把 NaCl 密钥，build 时显式传入
NACL_KEY=$(python -c "import os; print(os.urandom(32).hex())")
pyprotect build . --pub-key keys/license_ed25519.pub --nacl-key $NACL_KEY

# 2. 同一把密钥 + 同一个公钥注入运行时包源码（默认原地修改；加 --out 输出副本，避免密钥进入版本库）
pyprotect runtime-patch --pub-key keys/license_ed25519.pub --nacl-key $NACL_KEY

# 3. 构建"你专属"的运行时 wheel，分发给客户（私有源或直接发文件）
cd pyprotect-protected && python -m build
```

> ⚠️ 补丁后的运行时包含真实密钥，**严禁发布到公共 PyPI**，只能走私有渠道。

客户环境（安装厂商分发的补丁版）：

```python
import pyprotect_protected              # 自动注册 .enc 导入钩子
from pyprotect_protected import verify_license

if not verify_license():
    sys.exit(1)
```

---

## License

MIT
