# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
import re
import json
import base64
import datetime
from urllib.parse import quote
from collections import Counter, defaultdict

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


OVERVIEW_INSERT_MARKER = "<!--__PACKER_FINDER_OVERVIEW_ROWS__-->"


def _overview_meta_path(report_path):
    return f"{report_path}.meta.json"


def initialize_finder_overview_report(report_path):
    """初始化总览报告文件，写入HTML头部、样式和交互脚本"""
    report_title = "Finder 敏感信息扫描总览报告"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_template = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>{report_title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0 auto; max-width: 1600px; padding: 20px; background-color: #f8f9fa; color: #333; }}
        h1, h2 {{ text-align: center; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 15px rgba(0,0,0,0.1); background-color: #fff; }}
        th, td {{ padding: 12px 15px; border: 1px solid #ddd; text-align: left; word-break: break-all; }}
        th {{ background-color: #f2f2f2; font-weight: bold; }}
        .data-row:nth-child(even) {{ background-color: #f9f9f9; }}
        .data-row:hover {{ background-color: #e9ecef; cursor: pointer; }}
        .data-row.active {{ background-color: #d1e7fd; }}
        a {{ color: #007bff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .summary-found {{ color: #dc3545; font-weight: bold; }}
        .summary-not-found {{ color: #6c757d; }}
        .summary-error {{ color: #ffc107; }}
        .footer {{ text-align: center; margin-top: 30px; color: #888; font-size: 0.9em; }}
        .hidden {{ display: none; }}
        .detail-cell {{ padding: 0; }}
        .detail-container {{ padding: 20px; background-color: #fdfdfd; border-top: 2px solid #007bff; }}
        .tabs {{ display: flex; border-bottom: 1px solid #ccc; margin-bottom: 15px; flex-wrap: wrap; }}
        .tab-link {{ padding: 10px 15px; cursor: pointer; border: 1px solid transparent; border-bottom: none; margin-bottom: -1px; background: #f1f1f1; border-radius: 4px 4px 0 0; margin-right: 5px; }}
        .tab-link.active {{ background: #fff; border-color: #ccc #ccc #fff; }}
        .tab-content {{ padding: 10px; }}
        .match-list-item {{ list-style: none; padding: 10px; border: 1px solid #eee; margin-bottom: 8px; border-radius: 4px; background: #fff; }}
        .match-list-item:hover {{ background: #f7f7f7; }}
        .match-header {{ cursor: pointer; font-weight: bold; color: #c0392b; font-family: monospace; }}
        .match-source {{ font-size: 0.8em; color: #777; margin-left: 15px; }}
        .match-context {{ background-color: #f0f0f0; padding: 10px; border-radius: 4px; margin-top: 10px; font-family: monospace; white-space: pre-wrap; word-break: break-all; font-size: 0.9em; border-left: 3px solid #6c757d; }}
        .highlight {{ background-color: #ff9999; padding: 2px 0; border-radius: 2px; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>{report_title}</h1>
    <h2>报告生成时间: {timestamp}</h2>
    <table id="main-table">
        <thead>
            <tr>
                <th style="width:5%">序号</th>
                <th style="width:35%">目标URL (点击展开/折叠)</th>
                <th style="width:45%">结果摘要</th>
                <th style="width:15%">原始报告</th>
            </tr>
        </thead>
        <tbody>
{OVERVIEW_INSERT_MARKER}
        </tbody>
    </table>
    <div class="footer">
        <p>报告由 Packer-InfoFinder 工具生成</p>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const mainTableBody = document.querySelector('#main-table tbody');

            // --- BUG FIX: Unicode-safe Base64解码函数 ---
            function b64DecodeUnicode(str) {{
                try {{
                    return decodeURIComponent(atob(str).split('').map(function(c) {{
                        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                    }}).join(''));
                }} catch (e) {{
                    console.error("Base64 decoding failed:", e);
                    return '';
                }}
            }}

            mainTableBody.addEventListener('click', function(e) {{
                const dataRow = e.target.closest('.data-row');
                if (!dataRow) return;

                const detailRowId = `detail-${{dataRow.dataset.id}}`;
                let detailRow = document.getElementById(detailRowId);

                if (detailRow) {{
                    dataRow.classList.toggle('active');
                    detailRow.classList.toggle('hidden');
                }} else {{
                    dataRow.classList.add('active');
                    detailRow = document.createElement('tr');
                    detailRow.id = detailRowId;
                    const detailCell = detailRow.insertCell(0);
                    detailCell.colSpan = 4;
                    detailCell.classList.add('detail-cell');
                    dataRow.insertAdjacentElement('afterend', detailRow);

                    const jsonDataScript = document.getElementById(`json-${{dataRow.dataset.id}}`);
                    try {{
                        const b64Data = jsonDataScript.textContent.trim();
                        if (!b64Data) throw new Error("No data found.");

                        const jsonText = b64DecodeUnicode(b64Data);
                        if (!jsonText) throw new Error("Decoded data is empty.");

                        const findings = JSON.parse(jsonText);
                        detailCell.innerHTML = createDetailView(findings, dataRow.dataset.id);
                        attachDetailEventListeners(detailRow);
                    }} catch (err) {{
                        detailCell.innerHTML = `<div class="detail-container">无法加载详细信息: ${{err.message}}</div>`;
                    }}
                }}
            }});

            function createDetailView(findings, id) {{
                if (Object.keys(findings).length === 0) {{
                    return `<div class="detail-container">无详细信息</div>`;
                }}
                let tabsHtml = '<div class="tabs">';
                let contentHtml = '';
                let isFirstTab = true;
                let tabIndex = 0; // --- BUG FIX: 使用索引作为ID，更稳妥 ---

                for (const type in findings) {{
                    const safeId = `tab-${{id}}-${{tabIndex}}`;
                    tabsHtml += `<div class="tab-link ${{isFirstTab ? 'active' : ''}}" data-tab="${{safeId}}">${{escapeHtml(type)}} (${{findings[type].length}})</div>`;

                    let matchesHtml = '<ul style="padding:0;">';
                    findings[type].forEach((item, index) => {{
                        const contextId = `context-${{id}}-${{tabIndex}}-${{index}}`;

                        // --- 优化点: 在上下文中高亮显示匹配的敏感信息 ---
                        const safeMatch = escapeHtml(item.match);
                        const safeContext = escapeHtml(item.context);
                        // 使用 split 和 join 实现全局替换，比 replaceAll 兼容性更好
                        const highlightedContext = safeContext.split(safeMatch).join(`<span class="highlight">${{safeMatch}}</span>`);

                        matchesHtml += `
                            <li class="match-list-item">
                                <div class="match-header" data-target="${{contextId}}">
                                    ${{safeMatch}}
                                    <span class="match-source">${{escapeHtml(item.source)}}</span>
                                </div>
                                <div id="${{contextId}}" class="match-context hidden">
                                    ${{highlightedContext}}
                                </div>
                            </li>`;
                    }});
                    matchesHtml += '</ul>';

                    contentHtml += `<div id="${{safeId}}" class="tab-content ${{isFirstTab ? '' : 'hidden'}}">${{matchesHtml}}</div>`;
                    isFirstTab = false;
                    tabIndex++;
                }}
                tabsHtml += '</div>';

                return `<div class="detail-container">${{tabsHtml}}${{contentHtml}}</div>`;
            }}

            function attachDetailEventListeners(detailRow) {{
                detailRow.addEventListener('click', function(e) {{
                    if (e.target.classList.contains('tab-link')) {{
                        const tabId = e.target.dataset.tab;
                        detailRow.querySelectorAll('.tab-link').forEach(t => t.classList.remove('active'));
                        e.target.classList.add('active');
                        detailRow.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
                        detailRow.querySelector(`#${{tabId}}`).classList.remove('hidden');
                    }} else if (e.target.closest('.match-header')) {{
                        const header = e.target.closest('.match-header');
                        const contextDiv = document.getElementById(header.dataset.target);
                        if (contextDiv) {{
                            contextDiv.classList.toggle('hidden');
                        }}
                    }}
                }});
            }}

            function escapeHtml(str) {{
                if (typeof str !== 'string') return '';
                const p = document.createElement("p");
                p.textContent = str;
                return p.innerHTML;
            }}
        }});
    </script>
</body>
</html>
"""
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_template)
    try:
        trailer = html_template.split(OVERVIEW_INSERT_MARKER, 1)[1]
        meta = {
            "version": 1,
            "marker": OVERVIEW_INSERT_MARKER,
            "trailer_len": len((OVERVIEW_INSERT_MARKER + trailer).encode('utf-8')),
        }
        with open(_overview_meta_path(report_path), 'w', encoding='utf-8') as meta_file:
            json.dump(meta, meta_file, ensure_ascii=False)
    except Exception:
        pass


def parse_detailed_report(report_path):
    """解析单个sensitive_info.html文件，提取摘要和所有详细信息"""
    summary = "已扫描，未发现敏感信息"
    details = defaultdict(list)
    try:
        if BeautifulSoup is None:
            raise ImportError("缺少 beautifulsoup4 依赖")

        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        soup = BeautifulSoup(content, 'html.parser')

        # 新版报告优先：读取 <script type="application/json-base64"> 中的详情数据
        json_scripts = soup.select('script[type="application/json-base64"]')
        for script in json_scripts:
            raw_b64 = script.get_text(strip=True)
            if not raw_b64:
                continue

            try:
                b64_data = re.sub(r'\s+', '', raw_b64)
                decoded = base64.b64decode(b64_data).decode('utf-8')
                findings = json.loads(decoded)
            except Exception:
                continue

            if not isinstance(findings, dict):
                continue

            for finding_type, items in findings.items():
                if not isinstance(finding_type, str) or not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    details[finding_type].append({
                        "match": str(item.get("match", "")),
                        "source": str(item.get("source", "")),
                        "context": str(item.get("context", "")),
                    })

            # 新版报告解析成功后直接返回
            if details:
                summary_parts = [
                    f"{ftype}: {len(items)}"
                    for ftype, items in sorted(details.items(), key=lambda kv: len(kv[1]), reverse=True)
                ]
                return ", ".join(summary_parts), dict(details)

            # 找到新版数据但为空，说明未发现敏感信息
            return summary, {}

        # 旧版报告兼容解析
        if "未发现敏感信息" in content:
            return summary, {}

        findings_summary = Counter()
        sidebar_links = soup.select('.sidebar ul li a')
        for link in sidebar_links:
            match = re.match(r'^(.*?)(\d+)$', link.get_text(strip=True))
            if match:
                finding_type, count = match.groups()
                findings_summary[finding_type.strip()] = int(count)
        if findings_summary:
            summary_parts = [f"{ftype}: {count}" for ftype, count in findings_summary.most_common()]
            summary = ", ".join(summary_parts)

        sections = soup.find_all('h2')
        for section in sections:
            section_id = section.get('id')
            if not section_id:
                continue
            section_title = section_id.replace("_", " ")

            match_grid = section.find_next_sibling('div', class_='match-grid')
            if not match_grid:
                continue

            for item in match_grid.find_all('div', class_='match-item'):
                match_text = item.select_one('.match-text').get_text(strip=True) if item.select_one('.match-text') else ''
                match_source = item.select_one('.match-source').get_text(strip=True).replace('来源: ', '') if item.select_one('.match-source') else ''
                match_context = item.select_one('.match-context').get_text(strip=True) if item.select_one('.match-context') else ''
                details[section_title].append({
                    "match": match_text,
                    "source": match_source,
                    "context": match_context
                })

        return summary, dict(details)
    except Exception as e:
        return f"解析报告失败: {str(e)}", {}


def append_to_overview_report(index, url, summary, details, detailed_report_path):
    """向总览报告中追加一行记录及对应的Base64编码的JSON数据"""
    summary_class = "summary-not-found"
    if details and "失败" not in summary and "异常" not in summary:
        summary_class = "summary-found"
    elif "失败" in summary or "异常" in summary:
        summary_class = "summary-error"

    link = "无"
    if detailed_report_path and os.path.exists(detailed_report_path):
        relative_path = os.path.relpath(detailed_report_path, start=os.getcwd())
        link = f'<a href="{quote(relative_path.replace(os.sep, "/"))}" target="_blank" onclick="event.stopPropagation();">点击查看</a>'

    table_row = f"""
            <tr class="data-row" data-id="{index}">
                <td>{index}</td>
                <td><a href="{url}" target="_blank" onclick="event.stopPropagation();">{url}</a></td>
                <td class="{summary_class}">{summary}</td>
                <td>{link}</td>
            </tr>
    """

    try:
        json_string = json.dumps(details, ensure_ascii=False)
        json_bytes = json_string.encode('utf-8')
        b64_bytes = base64.b64encode(json_bytes)
        b64_string = b64_bytes.decode('ascii')
    except Exception:
        b64_string = ""

    json_script = f"""
            <script type="application/json-base64" id="json-{index}" class="hidden">
            {b64_string}
            </script>
    """
    return table_row + json_script


def append_row_to_overview_report(report_path, row_html):
    """增量追加一行记录到总览报告。

    实现方式：初始化时在 tbody 中写入固定 marker，并记录尾部固定内容的字节长度。
    追加时只覆写 `row_html + 固定尾部`，避免整文件 read/modify/write。
    """
    if not report_path or not row_html:
        return

    meta_path = _overview_meta_path(report_path)
    if not os.path.exists(report_path):
        initialize_finder_overview_report(report_path)

    try:
        with open(meta_path, 'r', encoding='utf-8') as meta_file:
            meta = json.load(meta_file)
        trailer_len = int(meta.get('trailer_len') or 0)
    except Exception:
        trailer_len = 0

    if trailer_len <= 0:
        with open(report_path, 'r+', encoding='utf-8') as f:
            content = f.read()
            tbody_pos = content.find('</tbody>')
            if tbody_pos == -1:
                return
            final_content = content[:tbody_pos] + row_html + content[tbody_pos:]
            f.seek(0)
            f.write(final_content)
            f.truncate()
        return

    marker_and_tail = None
    try:
        with open(report_path, 'rb') as f:
            f.seek(max(0, os.path.getsize(report_path) - trailer_len))
            marker_and_tail = f.read(trailer_len)
    except Exception:
        marker_and_tail = None

    if not marker_and_tail:
        return

    row_bytes = row_html.encode('utf-8')
    with open(report_path, 'r+b') as f:
        f.seek(max(0, os.path.getsize(report_path) - trailer_len))
        f.write(row_bytes)
        f.write(marker_and_tail)
        f.truncate()


def finalize_overview_report(report_path, all_rows_html):
    """将所有行数据写入报告并添加结尾"""
    if not all_rows_html:
        return
    with open(report_path, 'r+', encoding='utf-8') as f:
        content = f.read()
        tbody_pos = content.find('</tbody>')
        if tbody_pos != -1:
            final_content = content[:tbody_pos] + all_rows_html + content[tbody_pos:]
            f.seek(0)
            f.write(final_content)
            f.truncate()
