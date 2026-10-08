# 轻量级沙箱方案调研（AI Agent / 不可信代码执行）

> 调研时间：2026-10。重点对比 [strands-agents/box](https://github.com/strands-agents/box)（commit `2c874ea`）与 [microsoft/mxc](https://github.com/microsoft/mxc)（commit `7cd00d1`），两者都基于源码与仓库内设计文档阅读；第 5 节的其他方案基于公开资料，未逐一实测。

## 1. 结论速览

| | Strands Box | Microsoft MXC |
|---|---|---|
| 定位 | **Agent 安全运行时**：OS 沙箱 + 语义化策略引擎 + 出口网关 + 凭据注入 | **跨平台沙箱 SDK**：统一请求格式 → 选择后端 → 起一个受限进程/容器/VM |
| 核心价值 | “能不能做 + 在什么条件下做”（策略可以引用历史事件、时间） | “用同一份 JSON 策略，在 Win/Linux/macOS 上拿到各平台最强的隔离” |
| 平台 | 预览版仅 macOS（Apple silicon）；Linux 后端（namespace + seccomp）在代码中，未正式支持 | Windows（ProcessContainer 默认）、Linux（bubblewrap 默认）、macOS（Seatbelt） |
| 隔离层级 | 进程级（Seatbelt）；文档提到 MicroVM 档为规划 | 进程级 → 容器（LXC/WSLC）→ microVM（Hyperlight、Nanvix，实验性） |
| 网络控制 | 所有流量强制经过内置 egress 网关，按 host / method / path 做策略；网关 TLS 终止 | 按后端能力：Windows WFP 可按 IP/端口；bwrap 用 netns + slirp4netns + iptables；Seatbelt 只能全开/全关 + loopback |
| 凭据 | 网关注入（phantom token），Agent 拿不到真实密钥 | 不负责 |
| 审计 | 每个决策记录为 OTLP JSON | 诊断 / audit 模式（用于生成策略，非安全模式） |
| 接入方式 | `strands-box run` CLI + `box.toml` + `policy.dw`（Dogwood，Cedar 风格语法） | Rust / .NET / Node SDK 嵌入应用，或 `*-exec` 二进制吃 JSON |
| 许可 | Apache-2.0 | MIT |
| 代码规模 | ~22 万行 Rust | ~24 万行 Rust（+ .NET/Node SDK） |

**一句话**：MXC 解决“**怎么把进程关起来**”（隔离原语的跨平台抽象），Box 解决“**关起来之后 Agent 每一步该不该放行**”（策略 + 中介 + 凭据）。两者是互补关系，不是同类替代。

## 2. 沙箱方案的隔离光谱

“轻量级”通常指不需要完整 VM、启动在毫秒级的方案。按隔离边界从弱到强：

| 层级 | 机制 | 代表 | 启动 | 主要风险 |
|---|---|---|---|---|
| 语言/解释器级 | 解释器自己做 I/O 中介 | WASM（wasmtime）、Deno 权限、Box 的 Monty（Python）、Strands Shell | µs–ms | 解释器 bug 即逃逸；只能跑受支持的语言 |
| OS 进程沙箱 | 内核对单个进程树施加规则 | macOS Seatbelt、Linux Landlock + seccomp、namespaces/bubblewrap、nsjail、Windows AppContainer | ms | 共享宿主内核；内核漏洞可逃逸 |
| 容器 | namespace + cgroup + 镜像 | Docker、LXC、WSLC | 百 ms–s | 同上，攻击面更大但工具链成熟 |
| 用户态内核 | 拦截 syscall 自己实现 | gVisor | 百 ms | 兼容性、性能 |
| microVM | 硬件虚拟化 | Firecracker、Cloud Hypervisor、Kata、libkrun、Hyperlight、Nanvix | ~100 ms（快照可更快） | 需要 KVM/WHP；镜像管理 |
| 托管服务 | 以上任一 + 云端运维 | E2B、Modal、Daytona 等 | 视实现 | 数据出境、成本、厂商绑定 |

对 Agent 场景，关键的不只是“隔离多强”，还有三件事：**网络出口能否按域名控制**、**凭据是否会进入沙箱**、**是否兼容未经改造的 Agent（Claude Code / Codex / 自研 harness）**。

## 3. Strands Box 详解

### 3.1 架构

```
┌──── Agent 的 OS 沙箱（Seatbelt）────┐        ┌──── Box 可信进程（strands-box run，沙箱外）────┐
│ agent 进程                           │        │ broker ─┬─ Strands Shell（自研 shell 解释器）│
│ alias: zsh/bash/sh/python3/<mcp>  ───┼─ unix ─┤         ├─ Monty（Python 解释器，无自有 I/O）│
│                                      │ socket │         └─ MCP broker                        │
│ 所有出站流量（HTTPS_PROXY 强制）  ───┼────────┤ egress 网关（TLS 终止 + 凭据注入）            │
└──────────────────────────────────────┘        │ Dogwood 策略引擎 + 持久化事件历史 + 审计采集    │
                                                └──────────────────────────────────────────────┘
          工具（git/cargo）、本地 MCP server → 各自独立的“叶子沙箱”，无 alias、无回到 broker 的通道
```

两种强制手段并存，**互不覆盖**：

1. **OS 强制**：`box.toml` 中的文件 / exec 授权，启动前一次性生成 Seatbelt profile，由 trampoline 通过 `sandbox_init()` 施加后再 `exec` 目标程序。失败即拒绝启动，无降级模式。
2. **策略强制**：Agent 通过 alias 调用 shell / python / MCP、以及所有网络请求，都由可信进程中的组件代为执行，每个副作用（`shell:exec`、`fs:read`、`fs:write`、`net:connect`、`http:request`、`mcp:call`…）都要过 Dogwood 引擎，默认拒绝，`forbid` 优先于 `permit`。

### 3.2 亮点

- **时序/历史策略**：引擎有跨组件、跨运行持久化的事件历史，可写出“读过 `.env` 之后禁止任何外发请求”这类规则——这是防数据外泄（lethal trifecta）的关键能力，同类方案几乎都没有。
- **shell 命令拆成多个决策**：`zsh -c 'echo hi > notes.txt'` 会产生 `shell:exec(echo)` + `fs:write(notes.txt)` 两个决策；路径先解析符号链接再判定，并在解析后的句柄上执行，避免 TOCTOU。
- **凭据不入沙箱**：Agent 只拿到占位 token，网关在命中允许的目的地时替换为真实密钥（支持 AWS SigV4）。
- **硬底线（floors）**：`~/.ssh`、`~/.aws`、钥匙串、浏览器 profile、系统目录、本次运行的 `box.toml`/policy 本身，无论配置如何都拒绝（防止 Agent 改写下一次的策略）。
- **启动时披露所有授权**，强调“直接授权 = 绕过策略”，需要人工审阅。
- **一个 box 一个可信进程**：避免多租户密钥同进程。

### 3.3 局限（官方 `docs/design/limitations.md` 自述）

- 仅 macOS 预览；Linux 后端（原生 namespace + seccomp，不依赖 bwrap）尚未正式支持。
- **无资源限制**（CPU / 进程数 / 磁盘），无多租户隔离，不防内核漏洞。
- Agent 自己的 syscall（直接授权路径）和工具叶子沙箱内的文件操作**不进入策略历史**，因此时序规则只覆盖经过 Box 中介的操作。
- Shell / Monty 运行在可信进程里，解释器的内存安全缺陷 = 可信进程被攻破；宽泛的 `fs:*` permit 能让解释器读到 Agent 本身读不到的路径（解释器下面没有凭据底线）。
- 工具叶子沙箱比 Agent 沙箱更宽（可执行任意 helper、可 mmap 自己写出的代码、可探测 home 下文件是否存在）。
- `contain_egress = false` 的工具/MCP 会直接绕过网关。
- 审计记录无签名，可被篡改，投递尽力而为。

### 3.4 配置示例（摘自 `examples/claude-code`）

```toml
[agent]
command = ["~/.local/bin/claude", "--dangerously-skip-permissions"]
workspace = "~/box-tutorial/my-project"      # 只决定 cwd，不授予任何权限
[agent.filesystem]
read  = ["~/.local/share/claude/versions", ...]
list  = ["~/box-tutorial/my-project"]         # 项目文件只能通过 Bash 工具（受策略管控）访问
[egress.model]
destinations = ["bedrock-runtime.us-west-2.amazonaws.com"]
secret.ref   = "env://AWS_BEARER_TOKEN_BEDROCK"   # 网关注入
```

```cedar
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.path like "~/box-tutorial/my-project/*" };

forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.path == "~/box-tutorial/my-project/.env" };

forbid (principal, action == Box::Action::"net:connect", resource)
when { context.input has ip && context.input.ip like "169.254.*" };   // 云元数据
```

## 4. Microsoft MXC 详解

### 4.1 架构

```
你的应用 ──(ContainerRequest JSON / 类型化 API)──> MXC SDK（进程内，Rust/.NET/Node）
         ──> 校验 + 选择后端 ──> 隔离的 workload
```

同一份请求描述：`process`（命令、cwd、env、超时）、`filesystem`（`readonlyPaths` / `readwritePaths` / `deniedPaths`）、`network`（`egress` / `ingress` 方向化策略 + `runtimeConfig.networkProxy`）、`ui`（剪贴板、显示、输入注入）。支持 one-shot（`run` / `spawn`）和有状态生命周期（provision → start → exec → stop → deprovision），以及 PTY。

### 4.2 后端矩阵

| 平台 | 后端 | 机制 | 状态 |
|---|---|---|---|
| Windows | `processcontainer`（默认） | AppContainer / 进程安全环境 + WFP 出口过滤 + 每容器 WinHTTP 代理 | 稳定 |
| Windows | `windows_sandbox`、`wslc`、`isolation_session` | Windows Sandbox VM、WSL 容器等 | 实验/部分 |
| Linux | `bubblewrap`（默认） | user/pid/ipc/uts namespace；最小只读基线 + 显式 bind；网络用私有 netns + slirp4netns + iptables（无需 root） | 稳定 |
| Linux | `lxc` | LXC 容器，过滤网络需 root | 可用 |
| macOS | `seatbelt` | 生成 SBPL profile，在 fork/exec 之间 `sandbox_init()` | 稳定 |
| Linux/Win | `hyperlight` | Hyperlight micro-VM + Unikraft unikernel，快照恢复，跑 Python/Node 等源码 | 实验 |
| Linux/Win | `microvm`（Nanvix） | KVM/WHP，~100 ms 冷启动，~100 MB 内存 | 实验 |

### 4.3 亮点

- **诚实的能力报告**：后端无法执行的策略直接拒绝，而不是静默降级。例如 Seatbelt 没有按主机名/IP 过滤的原语，带 host 规则的请求会被拒；bwrap 网络依赖缺失时直接失败，绝不回退到共享宿主 netns。
- **bwrap 默认拒绝的文件系统基线**：只挂系统库/工具/`/etc` 等只读，`$HOME`、`/opt`、`/var`、`/run/user` 一律不可见；`deniedPaths` 会先解析符号链接，目录用 tmpfs 遮罩、文件用 `/dev/null` 遮罩。
- **`--clearenv`**：不继承宿主环境变量。
- **Windows 是一等公民**：WFP 可以按 IP/CIDR/端口/协议做出口过滤，这是 Linux/macOS 进程级后端都做不到的。
- **Audit 模式**（关闭隔离，记录访问，反推策略）+ `--dry-run` + 诊断工具，降低策略调试成本。
- 版本化 JSON schema，SDK 多语言。

### 4.4 局限

- **只管隔离，不管语义**：没有策略引擎、没有每次操作的审批、没有凭据注入、没有历史；Agent 层面的“读了密钥后不许外发”需要自己在上层实现。
- 网络能力随后端差异巨大：macOS 上只能全开/全关（+ loopback）；“按域名白名单”只能靠代理，而代理在 Seatbelt 下是**合作式**的（只是禁止了直连）。
- bwrap 网络模式依赖较多（slirp4netns、iptables-nft、nf_conntrack、util-linux），部分发行版/容器内不可用；需要 `unprivileged_userns_clone`。
- microVM 后端仍是实验性，需要 KVM/WHP。

## 5. 其他值得关注的方案（公开资料，未实测）

| 方案 | 机制 | 适合 |
|---|---|---|
| [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)（`srt`，Claude Code 沙箱所用） | Linux bubblewrap / macOS Seatbelt + 宿主侧 HTTP/SOCKS 代理按域名白名单 | 想要最小可用的“文件 + 域名白名单”沙箱，直接包住 CLI |
| OpenAI Codex CLI sandbox | macOS Seatbelt；Linux Landlock + seccomp | 参考其轻量实现 |
| [nsjail](https://github.com/google/nsjail) | namespaces + seccomp-bpf + cgroups + rlimit | Linux 上需要资源限制的一次性执行（OJ、CTF） |
| Landlock LSM | 非特权进程自限文件/TCP 端口访问（内核 ≥5.13，网络 ≥6.7） | 嵌入应用内部的自我限权 |
| [gVisor](https://gvisor.dev) | 用户态内核拦截 syscall | 容器场景想要比 runc 更强隔离 |
| Firecracker / Kata / Cloud Hypervisor | microVM | 多租户、服务端执行；E2B 等托管沙箱底层 |
| [microsandbox](https://github.com/microsandbox/microsandbox)（libkrun） | 本地 microVM | 本机上想要 VM 级隔离 |
| WASM（wasmtime / WASI） | 能力模型 + 线性内存 | 插件、受限语言运行时 |

## 6. 选型建议

1. **本地开发机跑编码 Agent（Claude Code / Codex 等）**
   - 只要“限制文件 + 域名白名单”：`sandbox-runtime` 或 MXC（bwrap/Seatbelt）+ 自建出口代理即可，成本最低。
   - 需要防数据外泄、凭据不落地、逐操作审计：Box 的模型最完整，但目前只有 macOS，且策略编写成本较高。
2. **自研产品需要嵌入沙箱能力（尤其要支持 Windows）**：MXC。它的 SDK + 多后端是目前覆盖面最广的开源方案；上层自行实现策略/代理。
3. **服务端多租户执行不可信代码**：进程级沙箱不够（Box、MXC 都明确不承诺跨租户隔离），用 Firecracker/gVisor/Kata 或托管服务；进程沙箱可作为 VM 内的第二层。
4. **组合思路（推荐的目标架构）**：外层 microVM/容器提供租户边界 → 内层 OS 进程沙箱（bwrap/Landlock/Seatbelt）限制 Agent → 出口一律走宿主侧代理（TLS 终止、域名/路径策略、凭据注入）→ 所有决策落审计日志。Box 的设计文档（`docs/design/decisions.md`，~1900 行）对每一层的取舍写得非常细，值得作为设计参考。

## 7. 设计要点 / 常见坑（两个项目文档里反复出现的）

- **Fail closed**：施加沙箱失败、后端不支持某条策略、依赖缺失 → 拒绝运行，而不是降级。
- **环境变量不继承**（`--clearenv` / 仅 `HOME`+`PATH`），否则宿主 token 直接进沙箱。
- **代理只是“建议”**：必须在 OS 层禁止直连，代理才是强制的；否则不读 `HTTPS_PROXY` 的程序可以绕过。
- **域名白名单 ≠ 安全**：允许的目的地就是外泄通道（如 GitHub gist、允许的 S3 桶），需要按 method/path 甚至历史事件判断。
- **云元数据地址**（`169.254.169.254`、`fd00:ec2::254`）要显式封禁，并在 DNS 解析后按 IP 再判一次。
- **符号链接 / TOCTOU**：先解析再判定，并对解析后的对象执行（Box Shell）；deny 遮罩要落在真实路径上（MXC bwrap）。
- **保护策略文件本身**：沙箱内可写的工具不能改写下一次运行的配置。
- **write + exec 同一路径** = 可以替换自己被允许执行的程序。
- **HOME / cwd 中的 dotfiles**（`.gitconfig`、`.npmrc`）会被工具当作用户级配置读取，是不可信工作区的注入点。
- **进程级沙箱不做资源限制**，需要另外配 cgroup / rlimit / 超时。

## 8. 下一步可做的验证

- [ ] 在 Linux 上实测 MXC bwrap 后端的启动延迟与网络模式依赖。
- [ ] 在 macOS 上跑 Box 的 `examples/claude-code`，验证 `.env` 读取后外发被拒的时序策略。
- [ ] 对比 `sandbox-runtime` 与 MXC bwrap 在同一 Agent 任务下的兼容性（git、npm、pip、cargo）。
- [ ] 评估 Box 的 egress 网关能否单独抽出，配合 MXC 做跨平台的“隔离 + 策略”组合。
