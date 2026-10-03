# ida-unicall

**IDA 插件：在 Hex-Rays 伪代码中右键一个函数调用，直接用 [unicall](../unicall) 模拟执行它。**

插件解决的是逆向分析中反复出现的场景：在 F5 伪代码里看到一行解密调用，例如

```c
str_decrypted = str_decrypt(src: str_cipher, n: 48, 35, &dword_61F2F0, n32: (char *)8);
```

传统做法是手工确认每个参数、切到 Python 里构造模拟脚本。本插件把这个流程压缩为右键一次：参数由 ctree 自动识别并预填，弹出的对话框中确认或修改后执行，结果直接显示并可一键写为调用点注释。

<!-- TODO: 放置插件运行截图（建议内容：伪代码视图中右键菜单 + 参数对话框 + 解密结果） -->
![screenshot](docs/images/screenshot.png)

## 工作方式

### 方案 A：伪代码右键（自动提取）

在 F5 视图中把光标放在调用表达式或被调函数名上，右键选择 `unicall: emulate this call`（快捷键 `Ctrl-Alt-E` 也可触发当前调用）。插件扫描当前函数的 ctree，尽力识别每个实参：

| 识别形态 | 示例 | 预填内容 |
|---|---|---|
| 数字字面量 | `48`、`35` | 整数值 |
| 全局地址 | `&dword_61F2F0` | 镜像内地址（unicall 按原始地址映射，可直接作指针） |
| 字符串字面量 | `"prefix %s"` | 字节串（UTF-8 + NUL） |
| 栈上立即数数组 | `str_cipher[0] = 0xF749...; ...` | 扫描全函数对该变量的立即数赋值，按元素小端序拼出完整字节串 |
| 无法识别 | 复杂表达式、运行期计算 | 留空，由人工填写 |

### 方案 B：手动模式

`Edit > Plugins > unicall`（快捷键 `Ctrl-Alt-U`）打开同一对话框，字段全空、调用地址默认为当前光标地址，适合无法自动提取或需要手工构造参数的场合。

### 人工确认环节（两种方案共有）

**插件从不静默执行模拟。** 自动提取只负责预填；对话框中可以逐项修改参数，点击 `Run` 后才在后台线程执行模拟（不阻塞 IDA UI），结果显示在输出区。存在留空字段时运行会被拒绝并提示参数编号。执行成功后可用 `Write comment at call site` 把结果写为该调用地址的注释。

### 参数字段格式

| 写法 | 含义 |
|---|---|
| `0x1A2B` 或 `-12` | 整数（值，或镜像内地址） |
| `"text"` | C 字符串（自动补 NUL） |
| `9c6e0c3a...` | 原始字节（偶数长度十六进制） |
| 留空 / `unknown` | 未知（运行前必须填写） |

仅由十六进制字符组成的整数必须带 `0x` 前缀，以与字节串区分。

## 安装

1. 将 unicall 安装进 IDA 使用的 Python 解释器：

   ```bash
   <ida-python> -m pip install -e <workspace>/unicall
   # 或
   <ida-python> -m pip install <workspace>/unicall/dist/unicall-0.1.0-py3-none-any.whl
   ```

2. 将 `src/unicall_ida.py` 单个文件复制到 IDA 插件目录：

   ```bash
   cp src/unicall_ida.py "<IDA>/plugins/unicall_ida.py"
   ```

3. 重启 IDA，Output 窗口出现 `[unicall_ida] loaded` 即安装成功。

依赖 Python 3.10+ 与 IDA 8.x/9.x（Hex-Rays 可用时启用伪代码集成，不可用时仅手动模式）。Qt 绑定优先使用 PySide6，回退 PyQt5。

## 开发

```bash
uv sync            # 解析依赖（unicall 走本地路径源）
uv run pytest -q   # argcodec 纯逻辑测试（无需 IDA，7 项）
```

IDA 相关代码（extractor / dialog / worker / 插件入口）依赖 IDA 运行环境，需在 IDA 内验证；仓库内测试只覆盖无 IDA 依赖的纯逻辑部分。

## 已知限制（MVP）

- 参数自动提取覆盖四种常见形态，复杂表达式（寄存器传出的指针、运行期计算长度）需人工填写
- 栈上立即数提取要求赋值下标从 0 连续；有空洞时整体留空待人工处理
- 模拟器实例按样本缓存复用；跨多次执行的堆状态不重置（可在 unicall 层扩展 reset）
- PE delay-load import 由 unicall 层的已知限制继承而来
- `max_instr` 默认 2 亿条指令，失控保护依赖该上限（详见 unicall README 的 timeout 说明）

## Roadmap

- “对被调函数全部调用点批量模拟”：右键被调函数名时枚举所有调用点逐个预填
- 从函数入口部分执行到调用点、用真实寄存器状态回填参数（覆盖运行期计算的参数）
- 结果自动重命名变量 / 传播字符串到 F5 注释

## License

MIT
