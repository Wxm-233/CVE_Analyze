#!/usr/bin/env python3
"""
筛选 Linux 内核中架构相关的 CVE 公告
用法: python3 filter_arch_cves.py [git_repo_path]
"""

import os
import sys
import re
import subprocess
from pathlib import Path
from datetime import datetime
import argparse
from cveCrossScopes import get_linux_cve_details

# 架构相关关键词（可以扩展）
ARCH_KEYWORDS = [
    # 处理器架构
    'x86', 'x86_64', 'amd64', 'i386', 'i686',
    'arm', 'arm64', 'aarch64',
    'mips', 'mips64',
    'powerpc', 'ppc', 'ppc64', 'ppc64le',
    'riscv', 'riscv64',
    's390', 's390x',
    'sparc', 'sparc64',
    'ia64', 'itanium',
    
    # 架构相关组件
    'kvm', 'hypervisor', 'virtualization',
    'smp', 'symmetric multiprocessing',
    'mmu', 'memory management unit',
    'tlb', 'translation lookaside buffer',
    'cpu', 'processor', 'core',
    
    # 指令集
    'sse', 'avx', 'avx2', 'avx512',
    'neon', 'simd',
    'vmx', 'svm',
    
    # 架构特定
    'intel', 'amd', 'qualcomm', 'apple silicon',
    'big.little', 'big-little',
    
    # 其他相关
    'microarchitecture', 'uarch',
    'speculative execution', 'spectre', 'meltdown',
    'side-channel', 'cache timing',
]

class ArchCVEFilter:
    def __init__(self, repo_path=None):
        if repo_path:
            self.repo_path = Path(repo_path)
        else:
            # 默认使用当前目录
            self.repo_path = Path.cwd()
        
        # 编译正则表达式（不区分大小写）
        self.arch_patterns = [re.compile(rf'\b{re.escape(keyword)}\b', re.IGNORECASE) 
                             for keyword in ARCH_KEYWORDS]
        
        # 结果存储
        self.cves = []
        # 结果存储（架构相关）
        self.arch_cves = []
        self.non_arch_cves = []
    
    def check_if_arch_related(self, content):
        """检查内容是否与架构相关"""
        content_lower = content.lower()
        
        # 方法1：简单关键词匹配
        for pattern in self.arch_patterns:
            if pattern.search(content):
                # print("匹配到关键词：{}".format(pattern))
                return True
        
        # 方法2：检查是否提到特定架构文件/目录
        arch_paths = [
            'arch/', 'arch/x86/', 'arch/arm/', 'arch/arm64/', 'arch/powerpc/',
            'arch/mips/', 'arch/s390/', 'arch/riscv/', 'arch/sparc/',
        ]
        
        for path in arch_paths:
            if path in content:
                return True
        
        return False
    
    def extract_cve_info(self, commit_msg):
        """从提交信息中提取 CVE 信息"""
        cve_id = None
        severity = None
        
        # 提取 CVE ID
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', commit_msg, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(0).upper()
        
        # 提取严重程度
        severity_patterns = [
            (r'Severity:\s*(\w+)', 1),
            (r'severity:\s*(\w+)', 1),
            (r'CRITICAL', 'CRITICAL'),
            (r'HIGH', 'HIGH'),
            (r'MEDIUM', 'MEDIUM'),
            (r'LOW', 'LOW'),
        ]
        
        for pattern, group in severity_patterns:
            match = re.search(pattern, commit_msg, re.IGNORECASE)
            if match:
                if isinstance(group, int):
                    severity = match.group(group).upper()
                else:
                    severity = group
                break
        
        return cve_id, severity
    
    def analyze_git_repo(self, limit=None):
        """分析 Git 仓库中的 CVE 提交"""
        try:
            # 切换到仓库目录
            original_dir = os.getcwd()
            os.chdir(self.repo_path)
            
            # 获取所有提交（每个提交对应一封邮件）
            cmd = ['git', 'log', '--pretty=format:%H%n%ad%n%s%n%b', '--date=short']
            if limit:
                cmd.extend(['-n', str(limit)])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"错误: 无法读取 Git 仓库: {result.stderr}")
                return False
            
            # 解析提交
            commits = result.stdout.strip().split('\n\n')
            
            for commit in commits:
                # print('提交记录：', commit)
                lines = commit.strip().split('\n')
                if len(lines) < 3:
                    continue
                
                commit_hash = lines[0]
                date = lines[1]
                subject = lines[2]
                body = '\n'.join(lines[3:]) if len(lines) > 3 else ''
                
                full_content = f"{subject}\n{body}"
                
                # 提取 CVE 信息
                cve_id, severity = self.extract_cve_info(full_content)
                if not cve_id:
                    continue  # 不是 CVE 公告
                
                # 检查是否与架构相关
                # is_arch = self.check_if_arch_related(full_content)
                
                cve_info = {
                    'id': cve_id,
                    'hash': commit_hash,
                    'date': date,
                    'subject': subject,
                    'severity': severity,
                    # 'is_arch': is_arch,
                    'content_preview': body[:200] + '...' if len(body) > 200 else body
                }
                
                self.cves.append(cve_info)
                # 根据是否为架构相关，放到不同的成员里
                # if is_arch:
                #     self.arch_cves.append(cve_info)
                # else:
                #     self.non_arch_cves.append(cve_info)
            
            os.chdir(original_dir)
            return True
            
        except Exception as e:
            print(f"分析过程中出错: {e}")
            return False
    
    def generate_report(self, output_file=None):
        """生成报告"""
        total_cves = len(self.arch_cves) + len(self.non_arch_cves)
        
        report = []
        report.append("=" * 80)
        report.append("Linux 内核架构相关 CVE 分析报告")
        report.append("=" * 80)
        report.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"仓库路径: {self.repo_path}")
        report.append(f"总共发现 CVE 数量: {total_cves}")
        report.append(f"架构相关 CVE 数量: {len(self.arch_cves)} ({len(self.arch_cves)/total_cves*100:.1f}%)")
        report.append(f"非架构相关 CVE 数量: {len(self.non_arch_cves)} ({len(self.non_arch_cves)/total_cves*100:.1f}%)")
        report.append("")
        
        # 架构相关 CVE 详情
        if self.arch_cves:
            report.append("架构相关 CVE 列表:")
            report.append("-" * 80)
            
            for cve in sorted(self.arch_cves, key=lambda x: x['date'], reverse=True):
                report.append(f"CVE ID: {cve['id']}")
                report.append(f"日期: {cve['date']}")
                report.append(f"严重程度: {cve['severity'] or '未知'}")
                report.append(f"主题: {cve['subject']}")
                report.append(f"提交哈希: {cve['hash'][:8]}")
                report.append(f"内容预览: {cve['content_preview']}")
                report.append("")
        
        # 按架构统计
        report.append("按架构分类统计:")
        report.append("-" * 80)
        
        arch_stats = {}
        for cve in self.arch_cves:
            content = f"{cve['subject']}\n{cve['content_preview']}".lower()
            for keyword in ARCH_KEYWORDS:
                if re.search(rf'\b{re.escape(keyword)}\b', content):
                    arch_stats[keyword] = arch_stats.get(keyword, 0) + 1
        
        for arch, count in sorted(arch_stats.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                report.append(f"{arch:20s}: {count:3d} 个 CVE")
        
        report.append("")
        report.append("=" * 80)
        
        report_text = '\n'.join(report)
        
        # 输出到文件或屏幕
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"报告已保存到: {output_file}")
        else:
            print(report_text)
        
        return report_text
    
    def export_to_csv(self, filename="arch_cves.csv"):
        """导出到 CSV 文件"""
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['CVE_ID', 'Date', 'Severity', 'Subject', 'Commit_Hash', 'Arch_Related']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for cve in self.arch_cves:
                writer.writerow({
                    'CVE_ID': cve['id'],
                    'Date': cve['date'],
                    'Severity': cve['severity'] or 'Unknown',
                    'Subject': cve['subject'],
                    'Commit_Hash': cve['hash'],
                    'Arch_Related': 'YES'
                })
            
            for cve in self.non_arch_cves:
                writer.writerow({
                    'CVE_ID': cve['id'],
                    'Date': cve['date'],
                    'Severity': cve['severity'] or 'Unknown',
                    'Subject': cve['subject'],
                    'Commit_Hash': cve['hash'],
                    'Arch_Related': 'NO'
                })
        
        print(f"CSV 文件已导出: {filename}")

def main():
    parser = argparse.ArgumentParser(description='筛选 Linux 内核架构相关 CVE')
    parser.add_argument('--repo_path', nargs='?', default='.', 
                       help='Git 仓库路径（默认当前目录）')
    parser.add_argument('-o', '--output', help='输出报告文件')
    parser.add_argument('-c', '--csv', action='store_true', 
                       help='导出为 CSV 文件')
    parser.add_argument('-l', '--limit', type=int, 
                       help='限制分析的提交数量')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='显示详细信息')
    
    args = parser.parse_args()
    
    # 初始化分析器
    filter_tool = ArchCVEFilter(args.repo_path)
    
    if args.verbose:
        print(f"正在分析仓库: {args.repo_path}")
        print(f"使用关键词: {', '.join(ARCH_KEYWORDS[:10])}...")
    
    # 分析仓库
    filter_tool.analyze_git_repo(args.limit)

    for i in range(len(filter_tool.cves)):
        cve = filter_tool.cves[i] 
        cve_result = get_linux_cve_details(cve['id'])
        cve['call_stack'] = cve_result['call_stack']
        cve['related_functions'] = cve_result['related_functions']
        cve['description'] = cve_result['description']
        filter_tool.cves[i] = cve        

    # if filter_tool.analyze_git_repo(args.limit):
    #     # 生成报告
    #     filter_tool.generate_report(args.output)
        
    #     # 导出 CSV
    #     if args.csv:
    #         filter_tool.export_to_csv()
        
    #     if args.verbose:
    #         print(f"分析完成！找到 {len(filter_tool.arch_cves)} 个架构相关 CVE")
    # else:
    #     print("分析失败！")

if __name__ == "__main__":
    main()