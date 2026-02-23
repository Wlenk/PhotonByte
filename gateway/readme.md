# 🛰️ PhotonByte - Gateway

**PhotonByte Gateway** 是一个基于 Rust & Tokio 构建的高性能异步 DNS 网关。它不只是简单的解析转发，而是通过**多源赛跑（Upstream Racing）与后台异步测速（TCPing Probing）**，动态进化你的网络访问路径。

## 🚀 核心特性

* **多源竞速引擎 (Concurrent Racing)**：同步向所有配置的上游 DNS（如 AliDNS, Google, Cloudflare）发起请求，毫秒级拾取首个响应，彻底终结等待。
* **智能节点进化 (Node Evolution)**：
* **抢占响应**：收到首个结果后立即返回（TTL 设为 60s），确保初次访问无感知。
* **后台探测**：异步对所有解析出的 IP 进行 TCP 443 端口握手测速。
* **缓存重塑**：筛选出物理延迟最低的“王者 IP”，以高 TTL（1小时）强行注入本地缓存。


* **洋葱架构 (Onion Middleware)**：拦截、缓存、测速、分发逻辑完全解耦，支持极速扩展黑名单或自定义过滤规则。
* **极致性能**：全量异步 IO 驱动，零阻塞设计，内存占用极低。

---

## 🏗️ 项目架构

```text
src/
├── core/        # 核心引擎：异步洋葱管道 (Middleware Pipeline)
├── protocols/   # 协议层：DNS 报文编解码与上下文封装
├── middlewares/ # 旁路层：LRU 缓存管理、域名黑名单拦截
└── upstream/    # 业务层：多源赛跑引擎、后台异步 TCPing 测速器
```

---

## 🛠️ 快速开始

### 1. 配置文件 `config.toml`

```toml
[server]
listen = "0.0.0.0:5354"

[[upstreams]]
name = "AliDNS"
address = "223.5.5.5:53"

[[upstreams]]
name = "Google"
address = "8.8.8.8:53"

[rules]
blacklist = ["ads.example.com", "track.evil.org"]
block_mode = "NxDomain"  # 或 "EmptyAnswer"
```

### 2. 运行

```bash
cargo run --release
```

## 🛡️ 设计哲学

> **"Not just resolving, but evolving."**
> 传统的 DNS 仅仅告诉你“它在哪”，而 PhotonByte Gateway 告诉你“哪条路最快”。通过不断的后台探测与缓存重塑，你的网络环境将随着使用时间的增长而自动进化。

  
  

  

** btw 这是GEMINI 生成的readme....