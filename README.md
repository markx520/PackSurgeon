# PackSurgeon

> 基于 AST 语法树与多引擎自适应的前端打包资产全生命周期逆向与资产挖掘工作台 (End-to-End AST-Driven Frontend Reconnaissance Platform)。

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/)
[![Node Version](https://img.shields.io/badge/Node-18+-orange.svg)](https://nodejs.org/)

---

## 1. 行业痛点与诞生背景

在现代 Web 攻防演习与资产测绘实践中，目标应用广泛采用 Webpack、Vite、Rollup 等打包器，业务路由、高危接口及云凭据均被高度内嵌于经过混淆压缩的异步分块（Chunk）中。

以往安全研究员开展前端资源逆向时面临极度严重的**工具链碎片化（Toolchain Fragmentation）**困境：
- **抓取层割裂**：传统爬虫只能抓取入口静态资源，面对 Cloudflare、人机滑块与反爬风控时无法捕获动态异步 Chunk；
- **脱壳层孤立**：现存 AST 解混淆工具仅能做单文件离线格式化，无法与动态抓取和资产扫描联动；
- **分析层原始**：老旧扫描器（如 JSFinder 等）完全依赖机械粗暴的静态正则，误报率极高且无法解析现代分块语法；
- **协同成本高昂**：研究员需要在 4 至 5 个互不相干的异构工具之间手动拷贝、搬运中间产物。

**PackSurgeon 绝非单点脚本的粗暴拼接，而是业内首个构建了从『反风控多引擎嗅探』到『AST 语法级分块脱壳』，再到『高信噪比业务接口微创提纯』全生命周期闭环的一体化工业级前端逆向工程工作台。**

---

## 2. 核心架构与四大工程支柱

PackSurgeon 采用严格的四层微内核与数据总线解耦拓扑（Microkernel & Pipeline Architecture）：

```
+-----------------------------------------------------------------------------------+
|                        [Layer 1] 统一控制中枢 (packsurgeon.py)                     |
|            CLI 调度器 | 参数标准化校验 | 退出码契约 | 自包含运行环境自检探针          |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     [Layer 2] 核心管道与数据总线 (core/pipeline.py)                 |
|             全自动自闭环编排流水线 (Run) | 上下文状态机流转 | 优雅降级容错            |
+-----------------------------------------------------------------------------------+
                                         |
          +------------------------------+------------------------------+
          |                              |                              |
          v                              v                              v
+-------------------+          +-------------------+          +-------------------+
|   [Engine 1: 嗅探] |          |   [Engine 2: 脱壳] |          |   [Engine 3: 提纯] |
| engines/crawler/  |          | engines/deobfusc/ |          | engines/analyzer/ |
|                   |          |                   |          |                   |
| - Camoufox C++内核 | -------> | - Webcrack AST引擎| -------> | - API 报文微创提炼 |
| - Patchright 无痕 |          | - 混淆变量重命名  |          | - 20+类云凭据特征 |
| - 全链路 HTTP 录制|          | - 异步Chunk分块解压|         | - 启发式去噪模型  |
+-------------------+          +-------------------+          +-------------------+
                                                                        |
                                                                        v
+-----------------------------------------------------------------------------------+
|                         [Layer 4] 资产大盘呈现与报告导出                           |
|              交互式 HTML 审计报告 | Excel 资产表格 | 结构化终端高信噪比总览          |
+-----------------------------------------------------------------------------------+
```

---

## 3. 环境准备

### 3.1 系统基线
- Python 3.8 或更高版本
- Node.js 18.0.0 或更高版本
- 跨平台支持：Windows / Linux / macOS

### 3.2 依赖安装

1. 克隆代码仓库：
   ```bash
   git clone https://github.com/markx520/PackSurgeon.git
   cd PackSurgeon
   ```

2. 安装 Python 核心依赖：
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

3. 安装前端 AST 引擎依赖：
   ```bash
   npm install
   ```

4. 运行环境自检：
   ```bash
   python packsurgeon.py doctor
   ```

---

## 4. 快速上手

### 4.1 一键全自动闭环审计（推荐）
单命令自动完成：动态风控自适应嗅探 -> 静态/动态文件全拦截 -> AST 语法树脱壳 -> 敏感凭据深度扫描 -> 交互式 HTML 大盘输出：
```bash
python packsurgeon.py run -u "https://example.com" -p "http://127.0.0.1:7890"
```

### 4.2 独立动态嗅探与抓包录制 (`crawl`)
仅使用抗检测浏览器内核对目标站点进行深度资产捕获与 HTTP 报文录制：
```bash
python packsurgeon.py crawl -u "https://example.com" -i -o "assets_example"
```
* `-i`：启用交互模式，支持人工操作复杂菜单以触发深层异步分块加载
* `--engine`：可选 `auto`（智能自适应）、`camoufox`、`patchright` 或 `chrome`

### 4.3 独立 AST 批量语法脱壳 (`unpack`)
对本地已保存的打包分块代码目录执行解混淆与模块结构还原：
```bash
python packsurgeon.py unpack -i "assets_example" -o "assets_example_已解混淆"
```

### 4.4 独立代码目录敏感凭据挖掘 (`scan`)
对已解包或本地源码目录进行深度特征审计：
```bash
python packsurgeon.py scan --dir "assets_example_已解混淆"
```

---

## 5. 核心 CLI 子命令矩阵

| 子命令 | 核心定位 | 典型使用场景 | 关键参数 |
| :--- | :--- | :--- | :--- |
| `run` | **全链路一体化流水线** | 端到端全自动闭环，一键产出最终资产与漏洞大盘 | `-u`, `-o`, `-p`, `-i`, `-s` |
| `crawl` | **多内核动态自适应嗅探** | 绕过现代反爬风控与人机挑战，抓取异步路由分块 | `-u`, `-i`, `--engine`, `--depth` |
| `unpack` | **AST 语法树脱壳解混淆** | 解压还原 Webpack 包结构，变量还原与语法美化 | `-i`, `-o` |
| `scan` | **敏感凭据与接口挖掘** | 离线/在线识别 AccessKey、云密钥、API 路由端点 | `--dir`, `-u`, `-l`, `--finder` |
| `doctor` | **基础设施健康诊断** | 检查本地 Python、Node.js 与浏览器驱动就绪状态 | 无 |

---

## 6. 自研算法护城河

1. **浏览器内核自适应调度模型**：
   底层内置启发式特征识别网络，根据目标风控强度、移动端触控形态及反爬特征，0 毫秒智能平滑路由至最优驱动内核，彻底攻克现代异步分块无法捕获的行业死穴。
2. **API 抓包报文微创手术刀 (`api_surgeon`)**：
   自主研发针对 HTTP 传输层报文的 AST 提纯算法，自动过滤 CDN、WAF 及前端监控类库（Sentry, Datadog等）的冗余请求头噪音，漂亮格式化巨型单行 JSON 契约。
3. **AST 语义级模块还原**：
   摆脱传统字符正则拼接的局限性，在 AST 抽象语法树层级重构作用域变量与模块调用关系，实现真正可读的高保真逆向。

---

## 7. 贡献者与致谢 (Contributors)

### 7.1 核心作者与维护者
- **[@markx520](https://github.com/markx520)**：PackSurgeon 平台总架构师、全生命周期流水线编排、多引擎自适应嗅探与微创提纯算法演进
- **[@TFour123](https://github.com/TFour123)**：Packer-InfoFinder 原作者
- **[@eonun](https://github.com/eonun)**：原版核心贡献者

<a href="https://github.com/markx520/PackSurgeon/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=markx520/PackSurgeon" alt="Contributors" />
</a>

### 7.2 上游基石项目
- [Webcrack](https://github.com/j4k0xb/webcrack)：先进的前端混淆与 Webpack 分块解压工具
- [Playwright](https://github.com/microsoft/playwright)：高可靠现代浏览器自动化测试框架

---

## 8. 法律与合规免责声明

1. 本工具仅面向经合法授权的企业内控审计、渗透测试演练及网络安全学术研究使用。
2. 使用者在对目标站点开展安全评估前，应确保已取得目标系统所有者的明确书面授权。
3. 严禁利用本项目涉及的代码、技术或方案从事任何危害国家安全、侵犯商业秘密或破坏计算机信息系统的违法犯罪行为。
4. 因使用者违规滥用造成的直接或间接法律责任，均由使用者本人独立承担，本项目开发者与贡献者不承担任何连带责任。

---

## 9. 许可证

本项目遵循 [Apache License 2.0](LICENSE) 开源协议。
