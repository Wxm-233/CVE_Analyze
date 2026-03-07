# extractor.py
import re
from pathlib import Path
from typing import Optional

def find_function_definition(function_name: str, src_root: str, max_lines: int = 400) -> Optional[str]:
    """
    在 src_root 下递归搜索可能包含 function_name 的 .c/.h 文件（先用简单的 grep）
    然后尝试从发现的文件中提取函数实现体（基于花括号配对）。
    返回文本（函数定义），若找不到则返回 None。
    """
    src = Path(src_root)
    # 先快速 grep 文件名（使用 Python 搜索避免依赖外部 grep）
    candidates = []
    for p in src.rglob("*.c"):
        try:
            txt = p.read_text(errors="ignore")
        except Exception:
            continue
        # 匹配函数定义头部比如 "static int fname(" 或 "int fname(const char *...)"
        if re.search(r'\b' + re.escape(function_name) + r'\s*\(', txt):
            candidates.append(p)
            if len(candidates) > 50:
                break
    # 逐个文件尝试提取函数体
    for f in candidates:
        text = f.read_text(errors="ignore")
        # 找到函数名出现的索引，向前找函数签名的起点
        for m in re.finditer(r'([A-Za-z0-9_]+)\s*\(', text):
            if m.group(1) != function_name:
                continue
            # 从 m.start() 向前找到行首作为签名行
            start_idx = text.rfind('\n', 0, m.start()) + 1
            # 从 m.start() 向后找到第一个 '{'
            brace_pos = text.find('{', m.end())
            if brace_pos == -1:
                continue
            # 从 brace_pos 开始配对括号
            idx = brace_pos
            depth = 0
            end_idx = None
            while idx < len(text):
                ch = text[idx]
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end_idx = idx + 1
                        break
                idx += 1
                # 为了避免极端长时间循环，设置限制
                if idx - brace_pos > 100000:
                    break
            if end_idx:
                snippet = text[start_idx:end_idx]
                # 如果太长，截取前后若干行
                lines = snippet.splitlines()
                if len(lines) > max_lines:
                    snippet = "\n".join(lines[:max_lines//2] + ["    /* ... omitted ... */"] + lines[-max_lines//2:])
                header = f"/* file: {f} */\n"
                return header + snippet
    return None