# cve_cross_scopes.py
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

# linux-cve-announce git 仓库克隆在当前目录 ./linux-cve-announce
LORE_REPO = os.environ.get("LORE_REPO", "linux-cve-announce/git/0.git")

def _git_show_commit_by_grep(repo_path: str, cve_id: str) -> Optional[str]:
    """在 repo_path 的 git log 中查找包含 CVE ID 的最新提交正文(message+body)"""
    try:
        cmd = ["git", "--git-dir", repo_path, "log", "--all", "--grep", cve_id, "-n", "1", "--pretty=format:%B"]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        return out.strip()
    except subprocess.CalledProcessError:
        return None

def _extract_call_stack(text: str) -> List[str]:
    """从邮件/提交文本中提取 call trace。尝试多种常见标识: 'Call trace:', 'Call Trace', 'Backtrace', 'Call stack' 等"""
    if not text:
        return []
    patterns = [
        r'Call trace:\s*(?:\n\s*(?:\S.*\n)+)',       # typical kernel message
        r'Call Trace:\s*(?:\n\s*(?:\S.*\n)+)',
        r'Call stack:\s*(?:\n\s*(?:\S.*\n)+)',
        r'Backtrace:\s*(?:\n\s*(?:\S.*\n)+)'
    ]
    for p in patterns:
        m = re.search(p, text, flags=re.IGNORECASE)
        if m:
            block = m.group(0)
            # 提取函数行（以名前缀或缩进为准）
            lines = block.splitlines()
            funcs = []
            for ln in lines[1:]:
                ln = ln.strip()
                if not ln:
                    continue
                # kernel calltrace lines often are like: func_name+0x123/0xabc [module]
                # 也可能是 "  [<ffff8880>] func+0x100/0x200"
                # 采集其中较短的 token
                token = ln.split()[0]
                funcs.append(token)
            if funcs:
                return funcs
    # fallback: 寻找形如 "funcname+0x.../0x..." 的所有出现
    all_funcs = re.findall(r'([A-Za-z0-9_]+(?:\+\S+)?)', text)
    # 过滤噪声
    candidates = [f for f in all_funcs if '+' in f or re.match(r'^[A-Za-z_][A-Za-z0-9_]+$', f)]
    # 去重且保留顺序
    seen = set()
    out = []
    for f in candidates:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out[:50]

def _related_function_names(call_stack: List[str]) -> List[str]:
    out = []
    for e in call_stack:
        # 去掉 +offset/.. 的部分
        name = e.split('+')[0]
        # 也去掉 [module] 或 [] 标注
        name = name.split('[')[0].strip()
        if name and name not in out:
            out.append(name)
    return out

def _guess_linux_version(text: str) -> Optional[str]:
    # 常见模式： "Linux 5.10-rc1", "linux 5.4", "This affects kernel 5.10 and earlier"
    m = re.search(r'kernel\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', text, flags=re.IGNORECASE)
    if m:
        return m.group(1)
    m2 = re.search(r'Linux\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', text, flags=re.IGNORECASE)
    if m2:
        return m2.group(1)
    return None

def get_linux_cve_details(cve_id: str, repo_path: Optional[str] = None) -> Dict:
    """
    返回结构:
    {
      "cve_id": "CVE-YYYY-NNNN",
      "description": "...",
      "call_stack": ["func+0x.../0x...", ...],
      "related_functions": ["func", ...],
      "linux_version": "5.10" or None,
      "raw_text": "original commit/message text"
    }
    """
    repo = repo_path or LORE_REPO
    commit_text = _git_show_commit_by_grep(repo, cve_id)
    if not commit_text:
        # 作为回退，尝试在 repo 的 mails 目录或其他文本文件搜索
        try:
            grep_cmd = ["grep", "-R", "-n", cve_id, repo]
            out = subprocess.check_output(grep_cmd, text=True, stderr=subprocess.DEVNULL)
            # 仅取第一处匹配文件的一些上下文
            first = out.splitlines()[0]
            # 不进一步读取太复杂，返回简化信息
            snippet = first
        except Exception:
            snippet = ""
        commit_text = snippet

    call_stack = _extract_call_stack(commit_text)
    related_funcs = _related_function_names(call_stack)
    linux_version = _guess_linux_version(commit_text)

    return {
        "cve_id": cve_id,
        "description": commit_text[:4000],  # 截断以免过长
        "call_stack": call_stack,
        "related_functions": related_funcs,
        "linux_version": linux_version,
        "raw_text": commit_text
    }