# pyprotect

Python 代码保护与授权工具集 — Cython 编译 / NaCl 加密 / Ed25519 License 三合一。

## 安装

```bash
pip install pyprotectx

# 需要 Cython 编译功能：
pip install pyprotectx[compile]
```

客户侧运行时依赖（轻量，只含 pynacl）：

```bash
pip install pyprotectx-protected
```

## 同类工具对比

| 特性 | **pyprotect** | PyArmor | pyconcrete | SOURCEdefender |
|------|:---:|:---:|:---:|:---:|
| 代码混淆 | Cython → .so + NaCl 加密 | 字节码混淆 + 函数→C | AES-128 加密 | AES-256 加密 |
| License 授权 | Ed25519 签名 + 机器绑定 | 机器绑定 + 过期 | 无 | 付费 SaaS（需联网） |
| 开源 / 免费 | MIT | 付费闭源 | Apache | 专有付费 |
| 运行时依赖 | pynacl（轻量） | pyarmor_runtime | C 扩展 | sourcedefender SDK |
| 反编译难度 | 原生机器码，不可逆 | 字节码可逆 | AES 可暴力破解 | AES 可暴力破解 |

**pyprotect 的差异化:**

- **三合一 CLI**: 代码混淆 + License 授权在一个工具里，不需要组合多个工具
- **Cython 原生机器码**: `.py` → `.so`，反编译几乎不可能（PyArmor 字节码混淆可逆）
- **完全离线**: 不依赖任何外部服务，密钥和授权全在本地（SOURCEdefender 需联网激活）
- **MIT 开源**: 无许可费用，自由使用和修改

> 密码学攻击提示：使用 `nacl.secret.secretbox` 库中的 `XSalsa20-Poly1305
> authenticated encryption` 算法加密，无法被暴力破解

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
pyprotect init . --packages myapp lib utils --keep-plain main.py
```

会在项目根目录生成 `pyprotect.yaml` 并复制 `_bootstrap.py` 和 `license_verify.py` 模板。

#### `pyprotect.yaml` 配置说明

```yaml
packages:             # 要保护的包目录（相对于项目根）
  - myapp
  - lib
keep_plain:           # 保留为明文 .py 的文件
  - main.py
ed25519_public_key: keys/license_ed25519.pub   # 公钥路径
```

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
| `--packages` / `--keep-plain` | 覆盖 yaml 配置 |

### 4. 目标项目接入

在项目入口 `main.py` 中：

```python
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

### 5. Docker 构建集成

```dockerfile
FROM python:3.12-slim AS build
RUN pip install pyprotectx[compile] pynacl
COPY . /project
WORKDIR /project
RUN pyprotect build . --pub-key keys/license_ed25519.pub

FROM python:3.12-slim AS runtime
COPY --from=build /project /app
RUN pip install pyprotectx-protected
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
MACHINE=$(cat /etc/machine-id)
pyprotect license generate --machine-id $MACHINE --expire-days 365 \
  --private-key keys/license_ed25519.key -o license.lic

# 3. 初始化并构建
pyprotect init . --packages myapp --keep-plain main.py
pyprotect build . --pub-key keys/license_ed25519.pub

# 4. 验证运行
LICENSE_FILE=license.lic LICENSE_MACHINE_ID=$MACHINE python main.py
```

---

## `pyprotectx-protected` 运行时包

客户侧只需安装这个轻量包：

```bash
pip install pyprotectx-protected
```

```python
import pyprotect_protected              # 自动注册 .enc 导入钩子
from pyprotect_protected import verify_license

if not verify_license():
    sys.exit(1)
```

---

## 授权校验行为（fail-closed）

`verify_license()` 默认**失败即拒绝**：

| 场景 | 结果 |
|------|------|
| 未设置 `LICENSE_FILE` / 文件不存在 / 签名无效 / 机器不匹配 / 已过期 | ❌ `valid=False`，建议业务退出 |
| 授权有效且未过期 | ✅ 放行 |

开发调试时若想跳过授权，必须**显式**设置：

```bash
export PYPROTECT_ALLOW_DEV=1   # 仅限开发环境，受保护产品请勿携带
```

> `pyprotect license verify` 在校验失败时以 exit code 1 退出，便于脚本化判断。

---

## License

MIT
