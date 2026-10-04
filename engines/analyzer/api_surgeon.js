#!/usr/bin/env node
/**
 * api-surgeon.js
 * API 抓包报文微创手术刀 (API Record Surgeon)
 * 作用: 解析 .http 抓包报文，剥离 WAF/CDN 冗余噪音，漂亮格式化巨型单行 JSON，提炼高信噪比业务契约
 */

const fs = require('fs');
const path = require('path');

// 常见传输层与 WAF 噪音请求头白名单过滤规则
const NOISY_HEADERS = new Set([
  'accept-encoding', 'connection', 'sec-ch-ua', 'sec-ch-ua-mobile',
  'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site',
  'server-timing', 'via', 'x-content-type-options', 'x-dsa-origin-status',
  'x-dsa-trace-id', 'x-firefox-spdy', 'x-tt-trace-tag', 'x-xss-protection',
  'cache-control', 'pragma'
]);

function parseHttpFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);

  let meta = '';
  let mode = 'NONE';
  const reqLines = [];
  const resLines = [];

  for (const line of lines) {
    if (line.startsWith('### ')) {
      meta = line.replace(/^###\s*/, '').trim();
      continue;
    }
    if (line.includes('>>> REQUEST >>>')) {
      mode = 'REQ';
      continue;
    }
    if (line.includes('<<< RESPONSE <<<')) {
      mode = 'RES';
      continue;
    }

    if (mode === 'REQ') reqLines.push(line);
    if (mode === 'RES') resLines.push(line);
  }

  return {
    meta,
    request: parseHttpSection(reqLines, true),
    response: parseHttpSection(resLines, false)
  };
}

function parseHttpSection(lines, isRequest) {
  let firstLine = '';
  const headers = {};
  let bodyStartIndex = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (i === 0 && (line.startsWith('HTTP/') || line.includes('HTTP/1.'))) {
      firstLine = line;
      continue;
    }
    if (i === 0 && isRequest) {
      firstLine = line;
      continue;
    }

    if (line.trim() === '') {
      bodyStartIndex = i + 1;
      break;
    }

    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      const k = line.slice(0, colonIdx).trim().toLowerCase();
      const v = line.slice(colonIdx + 1).trim();
      headers[k] = v;
    }
  }

  let rawBody = '';
  if (bodyStartIndex !== -1 && bodyStartIndex < lines.length) {
    rawBody = lines.slice(bodyStartIndex).join('\n').trim();
  }

  return { firstLine, headers, rawBody };
}

function distillHeaders(headers) {
  const clean = {};
  for (const [k, v] of Object.entries(headers)) {
    if (NOISY_HEADERS.has(k)) continue;

    // 智能脱敏/摘要长 Cookie
    if (k === 'cookie') {
      const parts = v.split(';').map(p => p.trim());
      const shortCookies = [];
      let wafBytes = 0;
      for (const p of parts) {
        if (p.startsWith('ssxmod_') || p.startsWith('acw_tc') || p.startsWith('_u') || p.length > 100) {
          wafBytes += p.length;
        } else {
          shortCookies.push(p);
        }
      }
      clean['cookie'] = `${shortCookies.join('; ')} [已自动脱敏 ${wafBytes} 字节高防 WAF 防爬 Cookie]`.trim();
      continue;
    }

    // 智能摘要超长 Token / 签名
    if (k === 'access-token' && v.length > 60) {
      clean[k] = `${v.slice(0, 24)}...${v.slice(-16)} (JWT 令牌, 长度: ${v.length})`;
      continue;
    }
    if (k === 'angry-dog' && v.length > 50) {
      clean[k] = `${v.slice(0, 16)}...${v.slice(-10)} (混淆签名, 长度: ${v.length})`;
      continue;
    }

    clean[k] = v;
  }
  return clean;
}

function prettifyJsonSafely(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return raw;
  }
}

function extractCoreBusinessData(parsedRes) {
  if (!parsedRes || typeof parsedRes !== 'object') return null;
  const summary = {};

  const d = parsedRes.data || parsedRes.result || parsedRes;
  if (!d) return summary;

  // 1. 票务/订单场景提炼
  if (d.orders && Array.isArray(d.orders) && d.orders[0]) {
    const o0 = d.orders[0];
    summary['订单场景'] = o0.shows?.[0]?.showName ? '演出购票确认预单' : '交易订单';
    if (o0.shows?.[0]) {
      const s0 = o0.shows[0];
      summary['演出名称'] = s0.showName;
      summary['演出场馆'] = s0.venue?.venueName;
      summary['演出城市'] = s0.cityName;
      summary['场次时间'] = s0.showTimeDesc;
      summary['退票政策'] = s0.showNotes?.[0]?.name;
    }
    if (o0.audiences && Array.isArray(o0.audiences)) {
      summary['绑定观演人'] = o0.audiences.map(a => `${a.name} (${a.idType}: ${a.idNo})`);
    }
  }

  // 2. 金额与价格项
  if (d.orders?.[0]?.priceItems) {
    summary['金额明细'] = d.orders[0].priceItems.map(p => `${p.priceItemName}: ¥${p.priceItemVal}`);
  }

  // 3. 用户会员信息
  if (d.userPrivileges) {
    summary['当前用户'] = `ID: ${d.userPrivileges.userId} (等级: ${d.userPrivileges.primeLevelName})`;
  }

  return Object.keys(summary).length > 0 ? summary : null;
}

function distillHttp(filePath) {
  const parsed = parseHttpFile(filePath);
  const cleanReqHeaders = distillHeaders(parsed.request.headers);
  const cleanResHeaders = distillHeaders(parsed.response.headers);

  const reqJson = prettifyJsonSafely(parsed.request.rawBody);
  const resJson = prettifyJsonSafely(parsed.response.rawBody);
  const coreBusiness = extractCoreBusinessData(resJson);

  return {
    file: path.basename(filePath),
    meta: parsed.meta,
    requestLine: parsed.request.firstLine,
    responseLine: parsed.response.firstLine,
    requestHeaders: cleanReqHeaders,
    requestPayload: reqJson,
    responseHeaders: cleanResHeaders,
    coreBusinessSummary: coreBusiness,
    responsePayloadFormatted: resJson
  };
}

function formatMarkdownReport(d) {
  return `# API 报文微创提纯报告: ${d.file}

> **接口元数据**：${d.meta || d.requestLine}  
> **响应状态**：${d.responseLine}  

---

## 1. 核心业务资产极速摘要 (Core Business Summary)
${d.coreBusinessSummary ? Object.entries(d.coreBusinessSummary).map(([k, v]) => `- **${k}**：${Array.isArray(v) ? v.join(', ') : v}`).join('\n') : '- 未解析出特定垂类业务特征'}

---

## 2. 精简请求信息 (Distilled Request)
- **请求方法与路径**：\`${d.requestLine}\`
- **关键请求头**：
\`\`\`json
${JSON.stringify(d.requestHeaders, null, 2)}
\`\`\`
- **请求 Payload (已格式化)**：
\`\`\`json
${JSON.stringify(d.requestPayload, null, 2)}
\`\`\`

---

## 3. 响应 Payload 漂亮结构化数据 (Prettified Response)
\`\`\`json
${JSON.stringify(d.responsePayloadFormatted, null, 2)}
\`\`\`
`;
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('用法: node api-surgeon.js <文件路径或目录> [--json] [--out <输出路径>]');
    process.exit(1);
  }

  const targetPath = path.resolve(args[0]);
  const isJson = args.includes('--json');
  let outIdx = args.indexOf('--out');
  let outFile = outIdx !== -1 ? args[outIdx + 1] : null;

  if (fs.statSync(targetPath).isDirectory()) {
    const files = fs.readdirSync(targetPath).filter(f => f.endsWith('.http'));
    console.log(`[START] 扫描到目录包含 ${files.length} 个 .http 报文，开始批量提炼索引...`);
    const results = [];
    for (const f of files) {
      try {
        const distilled = distillHttp(path.join(targetPath, f));
        results.push({
          file: f,
          meta: distilled.meta,
          method: distilled.requestLine.split(' ')[0],
          path: distilled.requestLine.split(' ')[1],
          summary: distilled.coreBusinessSummary
        });
      } catch (err) {
        // 忽略单文件解析异常
      }
    }

    let summaryMd = `# 抓包接口全景索引提纯表 (Total: ${results.length})\n\n`;
    summaryMd += `| 编号 / 报文文件 | 请求方式 | 目标接口路径 | 核心业务摘要 |\n| :--- | :--- | :--- | :--- |\n`;
    for (const r of results) {
      const biz = r.summary ? Object.entries(r.summary).map(([k, v]) => `${k}:${Array.isArray(v)?v[0]:v}`).join('; ') : '-';
      summaryMd += `| [${r.file}](${r.file}) | \`${r.method}\` | \`${r.path ? r.path.split('?')[0] : ''}\` | ${biz} |\n`;
    }

    const outIndexFile = path.join(targetPath, '_distilled_index.md');
    fs.writeFileSync(outIndexFile, summaryMd, 'utf8');
    console.log(`[SUCCESS] 批量提炼完成！全景索引已生成至: ${outIndexFile}`);
    return;
  }

  console.log(`[START] 正在微创手术提纯: ${targetPath}`);
  const distilled = distillHttp(targetPath);

  if (isJson) {
    console.log(JSON.stringify(distilled, null, 2));
    return;
  }

  const report = formatMarkdownReport(distilled);
  if (outFile) {
    fs.writeFileSync(outFile, report, 'utf8');
    console.log(`[SUCCESS] 提纯报告已保存至: ${outFile}`);
  } else {
    // 默认输出到同目录下的 .distilled.md
    const defaultOut = targetPath.replace(/\.http$/, '.distilled.md');
    fs.writeFileSync(defaultOut, report, 'utf8');
    console.log(`[SUCCESS] 提纯完毕！已写入: ${defaultOut}`);
    console.log('\n--- 核心业务摘要预览 ---\n');
    if (distilled.coreBusinessSummary) {
      for (const [k, v] of Object.entries(distilled.coreBusinessSummary)) {
        console.log(`- ${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
      }
    }
  }
}

main();
