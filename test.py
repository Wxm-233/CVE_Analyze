import git

# 打开仓库
repo = git.Repo('linux-cve-announce/git/0.git')

print(repo.bare)

# 遍历所有 commit（按照时间倒序，如果想正序可以加 reverse）
for commit in repo.iter_commits('--all'):
    # 邮件标题
    subject = commit.message

    # 邮件正文存放在文件 'm' 中
    try:
        # 读取 commit 下的 'm' 文件
        m_blob = commit.tree / "m"
        body = m_blob.data_stream.read().decode('utf-8', errors='ignore')
    except KeyError:
        # 如果某个 commit 没有 m 文件，跳过
        body = ""