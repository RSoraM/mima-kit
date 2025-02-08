import fs from 'node:fs'
import path from 'node:path'
import child_process from 'node:child_process'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// 定义输出目录
const esmDir = path.join(__dirname, 'dist/esm')
const cjsDir = path.join(__dirname, 'dist/cjs')

function compileTS() {
    // 编译 TypeScript 为 ESM
    child_process.execSync('tsc -p tsconfig.esm.json', { stdio: 'inherit' })
    // 编译 TypeScript 为 CJS
    child_process.execSync('tsc -p tsconfig.cjs.json', { stdio: 'inherit' })
}

// 创建 ESM 版 package.json
function createESMPackageJson() {
    const esmPackageJson = {
        type: 'module',
    }
    fs.writeFileSync(path.join(esmDir, 'package.json'), JSON.stringify(esmPackageJson, null, 2))
}

// 创建 CJS 版 package.json
function createCJSPackageJson() {
    const cjsPackageJson = {
        type: 'commonjs',
    }
    fs.writeFileSync(path.join(cjsDir, 'package.json'), JSON.stringify(cjsPackageJson, null, 2))
}

// 主函数
function build() {
    // 清理旧地输出目录
    if (fs.existsSync(esmDir)) {
        fs.rmSync(esmDir, { recursive: true, force: true })
    }
    if (fs.existsSync(cjsDir)) {
        fs.rmSync(cjsDir, { recursive: true, force: true })
    }

    // 执行编译
    compileTS()

    // 创建 package.json 文件
    createESMPackageJson()
    createCJSPackageJson()
}

build()
