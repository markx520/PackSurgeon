const fs = require('fs');
const path = require('path');
const { webcrack } = require('webcrack');

const inDir = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve('site_download_example');
const outDir = process.argv[3] ? path.resolve(process.argv[3]) : path.resolve('site_download_example_已解混淆');

async function processFile(filePath) {
    const relPath = path.relative(inDir, filePath);
    const outPath = path.join(outDir, relPath);
    const outDirPath = path.dirname(outPath);
    
    fs.mkdirSync(outDirPath, { recursive: true });

    if (filePath.endsWith('.js') || filePath.includes('akam')) {
        try {
            const code = fs.readFileSync(filePath, 'utf8').trim();
            
            // 1. 如果是 HTML 页面直接保留原样
            if (code.startsWith('<') && !filePath.includes('akam')) {
                fs.copyFileSync(filePath, outPath);
                return;
            }

            // 2. 智能识别并美化 JSON 数据（解决 Unexpected token 报错）
            if ((code.startsWith('{') && code.endsWith('}')) || (code.startsWith('[') && code.endsWith(']'))) {
                try {
                    const parsedJson = JSON.parse(code);
                    fs.writeFileSync(outPath, JSON.stringify(parsedJson, null, 2), 'utf8');
                    return;
                } catch (jsonErr) {
                    // 不是标准 JSON 则继续走 JS 解混淆
                }
            }
            
            console.log('[INFO] 正在解混淆:', relPath);
            const result = await webcrack(code);
            fs.writeFileSync(outPath, result.code, 'utf8');
            
        } catch (e) {
            // 3. 对非标准脚本/加密码流优雅降级复制，避免异常中断
            console.log(`[PASS] 非标准JS/加密码流已原样保留: ${relPath}`);
            fs.copyFileSync(filePath, outPath);
        }
    } else {
        fs.copyFileSync(filePath, outPath);
    }
}

async function walkSync(dir) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const fullPath = path.join(dir, file);
        if (fs.statSync(fullPath).isDirectory()) {
            await walkSync(fullPath);
        } else {
            await processFile(fullPath);
        }
    }
}

async function main() {
    console.log(`输入目录: ${inDir}`);
    console.log(`输出目录: ${outDir}`);
    console.log('开始批量解混淆...');
    fs.mkdirSync(outDir, { recursive: true });
    await walkSync(inDir);
    console.log('全部解混淆完毕！');

    // 自动无缝串联 js-ast-surgeon 实施 AST 微创提纯手术
    try {
        const { execSync } = require('child_process');
        const surgeonScript = path.join(__dirname, 'scripts', 'js-surgeon.js');
        if (fs.existsSync(surgeonScript)) {
            console.log('\n[INFO] 正在自动触发 js-ast-surgeon 实施 AST 微创去噪与大盘提纯...');
            execSync(`node "${surgeonScript}" "${outDir}"`, { stdio: 'inherit' });
        }
    } catch (err) {
        console.error('[WARN] 自动微创手术执行异常:', err.message);
    }

    // 自动无缝串联 api-record-surgeon 实施抓包报文全景提纯
    try {
        const { execSync } = require('child_process');
        const apiRecordsDir = path.join(inDir, '_api_records');
        const apiSurgeonScript = path.join(__dirname, 'api-surgeon.js');
        if (fs.existsSync(apiRecordsDir) && fs.existsSync(apiSurgeonScript)) {
            console.log('\n[INFO] 正在自动触发 api-record-surgeon 实施 HTTP 抓包报文全景提纯...');
            execSync(`node "${apiSurgeonScript}" "${apiRecordsDir}"`, { stdio: 'inherit' });
        }
    } catch (err) {
        console.error('[WARN] API 抓包微创手术执行异常:', err.message);
    }
}

main().catch(console.error);

