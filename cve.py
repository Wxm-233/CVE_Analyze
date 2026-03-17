#!/usr/bin/env python3
"""
Utilities for CVE analysis
"""

import re

def parse_introduced_version(content: str) -> str:
    """从邮件内容中解析bug引入的版本，选择最新的"""
    pattern = r'Issue introduced in (\d+\.\d+)(?:\.\d+)?'
    matches = re.findall(pattern, content)
    if matches:
        # 选择最新的版本（假设格式为X.Y或X.Y.Z，取最大的）
        versions = [tuple(map(int, v.split('.'))) for v in matches]
        latest = max(versions)
        return '.'.join(map(str, latest))
    return ""
