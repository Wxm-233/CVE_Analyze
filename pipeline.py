# pipeline.py
import os
from source_manager import ensure_kernel_checkout, run_ctags
from extractor import find_function_definition
from fetch import get_emails_sequentially
from cve import parse_introduced_version
from llm_safe import LLMQuery
import json
import ast
import re
import concurrent.futures

def main():
    emails = get_emails_sequentially()
    llm = LLMQuery()

    results_folder = "results_reverse"
    os.makedirs(results_folder, exist_ok=True)

    for email in emails[::-1]:  # 从最新邮件开始分析
        analyze_email(email, llm, results_folder)

def analyze_email(email, llm, results_folder):
    title = email['title']
    full_content = email['full_content']

    # 第一个LLM：初始分析
    analysis = llm.initial_analysis(full_content)

    if not analysis:
        print(f"Skipping email due to LLM error: {title}")
        return

    try:
        parsed = json.loads(analysis)
    except json.JSONDecodeError:
        try:
            parsed = ast.literal_eval(analysis)
        except Exception:
            print(f"Failed to parse LLM response for: {title}")
            return

    is_valid = parsed.get("is_valid", False)
    call_stacks = parsed.get("call_stacks", [])
    introduced_version = parsed.get("introduced_version", "")

    if not is_valid:
        return

    # 从邮件内容解析版本
    if not introduced_version:
        introduced_version = parse_introduced_version(full_content)
    if not introduced_version:
        print(f"No version found for: {title}")
        return

    # 获取内核源码
    src_path = ensure_kernel_checkout(introduced_version)
    if not src_path:
        print(f"Failed to checkout kernel for version {introduced_version}")
        return

    # 生成ctags
    run_ctags(src_path)

    # 提取函数定义
    func_defs = []
    n_stack = 0
    for stack in call_stacks:
        func_defs.append(f"/* Call stack {n_stack} */")
        n_stack += 1
        # Parallel extraction for functions in this stack
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(stack))) as executor:
            results = list(executor.map(lambda func: find_function_definition(func, src_path), stack))
            for defn in results:
                if defn:
                    func_defs.append(defn)

    if not func_defs:
        print(f"No function definitions found for: {title}")
        return

    func_defs_str = "\n\n".join(func_defs)

    # 第二个LLM：cross-scope判断
    judgment = llm.cross_scope_judgment(func_defs_str, full_content)

    if not judgment:
        print(f"LLM failed to give judgment for: {title}")
        return
    
    try:
        judgment_parsed = json.loads(judgment)
        is_cross_scope = judgment_parsed.get("is_cross_scope", False)
    except json.JSONDecodeError:
        print(f"Failed to parse LLM judgment for: {title}")
        return

    if is_cross_scope:
        result = {
            "title": title,
            "content": full_content,
            "introduced_version": introduced_version,
            "call_stacks": call_stacks,
            "functions": func_defs,
            "conflicting_resources": judgment_parsed.get("conflicting_resources", [])
        }
        cve_match = re.search(r'CVE-\d{4}-\d+', title)
        cve_id = cve_match.group(0) if cve_match else "unknown"
        result_file = os.path.join(results_folder, f"{cve_id}_result.txt")
        with open(result_file, 'w', encoding='utf-8') as f:
            f.write(f"Title: {title}\n\n")
            f.write(f"Introduced Version: {introduced_version}\n\n")
            f.write("Content:\n")
            f.write(full_content + "\n\n")
            f.write("Call Stacks:\n")
            for i, stack in enumerate(call_stacks):
                f.write(f"Stack {i}:\n")
                for func in stack:
                    f.write(f"  {func}\n")
                f.write("\n")
            f.write("Functions:\n")
            for func in func_defs:
                f.write(func + "\n")
            f.write("\nConflicting Resources:\n")
            for resource in judgment_parsed.get("conflicting_resources", []):
                f.write(f"  {resource}\n")

        print(f"Cross-scope bug found and saved for: {title}")

def test():
    email_file = "CVE-2026-23267"
    with open(email_file, 'r', encoding='utf-8') as f:
        body = f.read()
    
    email_test = {
        "title": "CVE-2026-23267",
        "full_content": "CVE-2026-23267\n\n" + body
    }

    llm = LLMQuery()
    analyze_email(email_test, llm, "results")

if __name__ == "__main__":
    main()