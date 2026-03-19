# extractor.py
import re
from pathlib import Path
from typing import Optional
import os

# Global cache for function definitions
func_cache = {}

def find_function_definition(function_name: str, src_root: str, max_lines: int = 400) -> Optional[str]:
    """
    在 src_root 下搜索 function_name 的定义，首先使用 ctags 文件加速查找，
    若找不到则回退到文件扫描。
    返回文本（函数定义），若找不到则返回 None。
    """
    if function_name in func_cache:
        return func_cache[function_name]
    
    src = Path(src_root)
    tags_file = src / "tags"
    
    # Try ctags first
    if tags_file.exists():
        try:
            with open(tags_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.startswith(function_name + '\t'):
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            file_path = src / parts[1]
                            line_str = parts[2].rstrip(';"')
                            try:
                                line_num = int(line_str)
                            except ValueError:
                                continue
                            result = extract_function_from_file(file_path, line_num, function_name, max_lines)
                            if result:
                                func_cache[function_name] = result
                                return result
        except Exception:
            pass  # Fall back to scan
    
    # Fallback to file scan
    result = find_function_definition_scan(function_name, src_root, max_lines)
    if result:
        func_cache[function_name] = result
    return result

def extract_function_from_file(file_path: Path, line_num: int, function_name: str, max_lines: int) -> Optional[str]:
    """
    从指定文件和行号开始提取函数定义。
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return None
    
    if line_num < 1 or line_num > len(lines):
        return None
    
    # Start from the line, find function signature backwards
    start_line = line_num - 1  # 0-based
    while start_line > 0:
        line = lines[start_line].strip()
        if re.search(r'\b' + re.escape(function_name) + r'\s*\(', line):
            break
        start_line -= 1
    else:
        return None  # Not found
    
    # Find opening brace
    text = ''.join(lines[start_line:])
    brace_pos = text.find('{')
    if brace_pos == -1:
        return None
    
    # Pair braces
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
        if idx - brace_pos > 100000:
            break
    
    if end_idx is None:
        return None
    
    snippet = text[:end_idx]
    # Truncate if too long
    snippet_lines = snippet.splitlines()
    if len(snippet_lines) > max_lines:
        snippet = "\n".join(snippet_lines[:max_lines//2] + ["    /* ... omitted ... */"] + snippet_lines[-max_lines//2:])
    
    header = f"/* file: {file_path} */\n"
    return header + snippet

def find_function_definition_scan(function_name: str, src_root: str, max_lines: int) -> Optional[str]:
    """
    回退方法：扫描所有 .c 文件查找函数定义。
    """
    src = Path(src_root)
    candidates = []
    for p in src.rglob("*.c"):
        try:
            txt = p.read_text(errors="ignore")
        except Exception:
            continue
        if re.search(r'\b' + re.escape(function_name) + r'\s*\(', txt):
            candidates.append(p)
            if len(candidates) > 50:
                break
    for f in candidates:
        text = f.read_text(errors="ignore")
        for m in re.finditer(r'([A-Za-z0-9_]+)\s*\(', text):
            if m.group(1) != function_name:
                continue
            start_idx = text.rfind('\n', 0, m.start()) + 1
            brace_pos = text.find('{', m.end())
            if brace_pos == -1:
                continue
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
                if idx - brace_pos > 100000:
                    break
            if end_idx:
                snippet = text[start_idx:end_idx]
                lines = snippet.splitlines()
                if len(lines) > max_lines:
                    snippet = "\n".join(lines[:max_lines//2] + ["    /* ... omitted ... */"] + lines[-max_lines//2:])
                header = f"/* file: {f} */\n"
                return header + snippet
    return None