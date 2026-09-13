# AGENTS.md

## 项目概述

- wolfssh + wolfssl superbuild 工程
- 用于与 PKIX-SSH 服务端互操作
- 最终目标:
  - 支持 windows 和 linux 上与OpenSSH 风格的一致的客户端工具集：ssh、scp、sftp
  - 工具集全体支持 **x509 证书认证 (RFC 6187)**
  - 支持 python wrapper
    - 使 windows 和 linux 上导入 wrapper 后可以以动态库符号调用实现类似 paramiko 的 ssh 访问
    - 可以在 paramiko 的源码最小改动，比如新增 `__superinit__` 通过本工程获取到 ssh 真实的 fd 喂给原本的 paramiko 模块

## 构建

```bash
make all      # 清理产物模块 构建windows和linux产物
make linux    # 构建 Linux 二进制 → out/release/linux/bin/
make windows  # 构建 Windows (MinGW 交叉编译)
make clean    # 清理 out/
```

**Linux 构建配置：**
```
--enable-certs --enable-sshclient --enable-scp --enable-sftp --enable-fwd
```

## 仓库结构

| 路径              | 说明                                                |
| ----------------- | --------------------------------------------------- |
| `CMakeLists.txt`  | Superbuild 编排（ExternalProject）                  |
| `Makefile`        | 顶层入口                                            |
| `wolfssh/`        | Git subtree — wolfssh v1.5.0-stable，**含本地修改** |
| `wolfssl/`        | Git subtree — wolfssl v5.9.1-stable，未修改         |
| `out/`            | 构建产物（不纳入版本控制，构建后临时生成）          |
| `local-fwd.patch` | 端口转发参考 patch（已包含在源码中，仅保留参考）    |
| `python/`         | 预计给 python 的 wrapper 准备的目录                 |

## 修改边界

- `wolfssh/apps/wolfssh/` — wolfssh 客户端主程序（wolfssh.c, common.c/h）
- `wolfssh/wolfssh/test.h` — 平台抽象（Unix socket、网络工具函数）
- `wolfssh/examples/client/` — scp/sftp 共享代码（common.c/h）
- `wolfssh/examples/scpclient/` — scp 客户端
- `wolfssh/examples/sftpclient/` — sftp 客户端
- `CMakeLists.txt` — 构建配置
- **其它模块的修改必须与用户确认**

## 关键代码入口

- `wolfssh/src/internal.c` — SSH 协议核心，含 RFC 6187 x509 认证、direct-tcpip 和 direct-streamlocal@openssh.com 通道
- `wolfssh/apps/wolfssh/wolfssh.c` — wolfssh 客户端主程序，含：
  - `struct config` / `config_parse_command_line()` — 参数解析
  - `localForwardLoop()` — `-L` 端口转发循环（多监听器 + 多并发连接）
  - `wolfSSH_Client()` — 主函数流程
- `wolfssh/apps/wolfssh/common.c` — 密钥加载、known_hosts 校验、SSH config 解析
- `wolfssh/examples/client/common.c` — scp/sftp 共享的密钥加载和 SSH config 解析
- `wolfssh/examples/portfwd/portfwd.c` — 端口转发参考实现

## 已实现功能

| 功能               | OpenSSH 等价                       | 状态            |
| ------------------ | ---------------------------------- | --------------- |
| 远程命令执行       | `ssh user@host "cmd"`              | ✅               |
| 指定密钥/用户/端口 | `-i` / `-l` / `-p`                 | ✅               |
| x509 证书认证      | N/A                                | ✅ (`-X`)        |
| SSH config 解析    | `~/.ssh/config`                    | ✅               |
| 退出码透传         | 自动                               | ✅               |
| 配置打印           | `ssh -G`                           | ✅               |
| 本地端口转发       | `ssh -L [bind:]port:host:hostport` | ✅               |
| Unix socket 转发   | `ssh -L /local.sock:/remote.sock`  | ✅               |
| 多个 `-L`          | `ssh -L p1:h1:hp1 -L p2:h2:hp2`    | ✅               |
| 并发转发连接       | 自动                               | ✅（最多 64 个） |
| SCP 上传/下载      | `scp`                              | ✅               |
| SFTP 交互/一键     | `sftp`                             | ✅               |

## 已知问题

1. **PTY 模式 Segfault** — `wolfssh -t` 触发 SIGSEGV，影响交互式终端
2. **`-l` + `-p` 组合 munmap_chunk 崩溃** — 命令执行成功但退出时 core dump
3. **`-E` 日志文件未生成** — 参数可接受但不产出文件
4. **`-N` 不保持连接** — 与 OpenSSH 行为不一致（单独使用时立即退出，但配合 `-L` 时隧道正常工作）
5. **非交互模式 `Error reading stdin` 提示** — 不影响功能
6. **端口转发远端目标限制** — 对端 PKIX-SSH 未监听 `127.0.0.1`，转发目标须使用具体 IP（非代码缺陷）

## 测试

- 测试环境：Docker 容器 `ee9f2a54a94a` 内通过 wolfssh/wolfscp/wolfsftp 连接 PKIX-SSH 服务端
- 服务端：PKIX-SSH 16.2 @ 192.168.2.62:22 (aarch64)
- 部署：`sudo docker cp out/release/linux/bin/. ee9f2a54a94a:/opt/wolfssh/`
- 容器内执行需设置 `LD_LIBRARY_PATH=/opt/wolfssh/lib`
- 测试报告 `test-report.html`（仅在用户指定进行测试时生成）

### 测试报告格式模板

生成测试报告时严格按照以下结构和格式，文件名 `test-report.html`，使用独立 HTML 文件（内联 CSS，无外部依赖）：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>wolfssh 客户端工具测试报告</title>
<style>
  /* 内联样式：表格、代码块、状态标记等 */
  body { font-family: -apple-system, "Segoe UI", sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #fff; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; }
  th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
  th { background: #f5f5f5; }
  pre { background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 4px; overflow-x: auto; }
  .pass { color: #22863a; } .warn { color: #b08800; } .fail { color: #cb2431; } .ext { color: #0366d6; }
  .note { background: #fff8c5; border-left: 4px solid #b08800; padding: 8px 12px; margin: 8px 0; }
  h1 { border-bottom: 2px solid #333; } h2 { border-bottom: 1px solid #ddd; }
</style>
</head>
<body>
<h1>wolfssh 客户端工具测试报告</h1>
<section class="env">
  <!-- 测试环境信息 -->
</section>

<h1>wolfssh（SSH 客户端）</h1>
<h2>测试用例名称</h2>
<h3>测试指令</h3>
<pre><code>完整可复制的命令</code></pre>
<h3>终端回显</h3>
<pre><code>实际终端输出，包含 EXIT=&lt;code&gt;</code></pre>
<div class="note">（可选）对异常行为或已知问题的说明</div>

<!-- wolfscp / wolfsftp 同上结构 -->

<h1>与 OpenSSH 用法对比</h1>
<!-- 命令行语法对比表格 -->
<!-- 默认行为对比表格 -->
<!-- 测试结果总结表格 -->

<h1>已知问题</h1>
<!-- 编号列表 -->
</body>
</html>
```

状态标记使用 CSS class：
- `<span class="pass">✅ 兼容</span>`
- `<span class="warn">⚠️ 部分兼容</span>`（附说明）
- `<span class="fail">❌ 缺失</span>`
- `<span class="ext">🆕 扩展功能</span>`

### 测试用例覆盖要求

**wolfssh（SSH 客户端）— 19 项：**
1. 版本信息显示（`-V`）
2. 远程命令执行（`user@host "cmd"`）
3. 多命令执行（`"cmd1 && cmd2"`）
4. 指定密钥文件（`-i`）
5. 指定用户名和端口（`-l` / `-p`）
6. 强制 x509 认证模式（`-X`）
7. 日志输出到文件（`-E`）
8. 配置打印（`-G`）
9. 远程命令退出码传递（`"exit N"` → 本地 EXIT=N）
10. 错误密钥认证失败（预期失败）
11. 连接错误端口（预期失败）
12. 不执行远程命令（`-N`）
13. 二进制数据传输（`dd | wc -c`）
14. 交互式终端登录（`-t`）+ 强制 PTY + 远程命令（`-t "cmd"`）
15. 本地端口转发（`-L`）— 基本转发
16. 本地端口转发（`-L`）— 隧道数据传输
17. 本地端口转发（`-L`）— 多并发连接
18. Unix socket 转发（`-L /local.sock:/remote.sock`）
19. Unix socket 转发（`-L port:/remote.sock`）— TCP 到远端 socket

**wolfscp（SCP 客户端）— 5 项：**
1. 帮助信息（`-h`）
2. 文件上传（本地→远程）+ 验证
3. 文件下载（远程→本地）+ 验证
4. 大文件传输与 MD5 校验（512KB）
5. 无密钥参数自动读取 SSH config

**wolfsftp（SFTP 客户端）— 9 项：**
1. 帮助信息（`-h`）
2. 交互式目录浏览（`pwd` / `ls`）
3. 文件上传 put（交互模式）
4. 文件下载 get（交互模式）
5. 目录操作（`mkdir` / `cd` / `pwd`）
6. 一键上传模式（非交互）
7. 一键下载模式（非交互）
8. 大文件传输与 MD5 校验（512KB）
9. 无密钥参数自动读取 SSH config

### 测试报告书写要点

- 每个测试用例必须包含**完整可复制的命令**和**实际终端输出**（含 `EXIT=<code>`）
- 大文件传输需同时记录本地和远程的 MD5 值
- 交互式 SFTP 测试用 `printf "cmd1\ncmd2\nquit\n" | wolfsftp ...` 形式，非手动交互
- 兼容性标记：✅ 兼容 / ⚠️ 部分兼容（附说明） / ❌ 缺失 / 🆕 扩展功能
- 已知问题标注是否影响功能
- 测试结果总结表必须有合计行

## Git 提交规范

### Jira ID 强制要求

- **每次提交必须包含 Jira ID**，提交前必须向用户询问
- 未提供 Jira ID 则**禁止执行 `git commit`**
- 格式示例：`JETTA-6434`、`PRO-38854`

### Commit 消息格式

```
<type>(<scope>): [<JIRA-ID>] <description>
```

- `type`：**必填**，`feat` / `fix` / `build` / `docs` / `test` / `refactor` / `chore`
- `scope`：**必填**，模块名
- `[JIRA-ID]`：**必填**，方括号包裹
- `<description>`：**使用中文**
- **仅标题，不写正文**
`<description>`：**使用中文**
-