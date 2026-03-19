import git
from typing import List, Dict

def get_emails_sequentially(repo_path: str = 'linux-cve-announce/git/0.git') -> List[Dict[str, str]]:
    """
    按顺序抓取邮件，提取标题与正文。
    返回列表，每个元素为 {'title': str, 'full_content': str}
    """
    repo = git.Repo(repo_path)
    emails = []
    # 按时间正序遍历（从最早到最新）
    for commit in repo.iter_commits('--all', reverse=True):
        subject = commit.message.strip()
        try:
            m_blob = commit.tree / "m"
            body = m_blob.data_stream.read().decode('utf-8', errors='ignore').strip()
            # 从 "Description ===========" 开始截取，忽略上边的部分
            start_marker = "Description\n==========="
            start_index = body.find(start_marker)
            if start_index != -1:
                body = body[start_index + len(start_marker):].strip()
        except KeyError:
            body = ""
        full_content = subject + "\n\n" + body
        emails.append({
            'title': subject,
            'full_content': full_content
        })
    return emails

if __name__ == "__main__":
    emails = get_emails_sequentially()
    print(f"Total emails: {len(emails)}")
    for i, email in enumerate(emails[:5]):  # 打印前5个
        print(f"Email {i+1}:")
        print(f"Full Content: {email['full_content']}")

        print("-" * 50)