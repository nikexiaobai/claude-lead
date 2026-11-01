# 运行时验收基线（mentor 亲自执行）

审查 diff 与测试报告不够。凡是“能跑起来的东西”，mentor 都要亲手启动并用真实请求走一遍关键链路。Codex 自述“完成”不作为证据。

## 1. 准备

```bash
cd <project>
git status --short          # 改动范围、有没有越界文件
npm test                    # 或项目测试命令；记录退出码
mkdir -p /tmp/verify-<task>
PORT=3456 DB_PATH=/tmp/verify-<task>/db.sqlite npm start > /tmp/verify-<task>/server.log 2>&1 &
```

用临时数据库和非默认端口，避免污染交付数据；验完 kill 进程并清理临时目录。

## 2. 认证与安全（有用户系统时逐条跑）

```bash
B=http://127.0.0.1:3456; C=/tmp/verify-<task>/cookies.txt

curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' $B/admin          # 期望 302 登录页
curl -s -i -c $C -b $C -X POST $B/register \
  -d 'email=v@example.com&nickname=V&password=verifypass123&confirm=verifypass123' | grep -i set-cookie
curl -s -o /dev/null -w '%{http_code}\n' -b $C $B/admin                    # 期望 200
curl -s -X POST $B/login -d 'email=v@example.com&password=wrongpass123' | grep -o '统一错误提示'
curl -s -X POST $B/login -d 'email=nobody@example.com&password=wrongpass123' | grep -o '统一错误提示'
curl -s -o /dev/null -w '%{http_code}\n' -X POST $B/login \
  --data-urlencode "email=' OR 1=1 --" --data-urlencode "password=x"      # 期望 400/401
curl -s -o /dev/null -w '%{http_code}\n' -b 'sid=s%3Afake.sig' $B/admin    # 期望 302/401
curl -s -o /dev/null -w '%{http_code}\n' -b $C -c $C -X POST $B/logout
curl -s -o /dev/null -w '%{http_code}\n' -b $C $B/admin                    # 期望 302
```

XSS：发一篇含 `<script>` 的内容，详情页必须转义（页面源码里不能出现可执行 `<script>`）。
字段名以项目实际为准（常见是 `body` 而不是 `content`）。

数据库抽查：

```bash
sqlite3 /tmp/verify-<task>/db.sqlite \
  "select email, substr(password_hash,1,7), length(password_hash) from users;"   # $2a$/$2b$、60
```

## 3. 代码抽查

- 登录后 `session.regenerate()`；登出 `destroy()`。
- SQL 全部参数化，无字符串拼接。
- 模板默认转义；Markdown 原始 HTML 清洗。
- Cookie：`HttpOnly`、`SameSite=Lax`、密钥来自环境变量。
- 没有密钥、默认口令被硬编码进提交文件。

## 4. 判定线

1. README 能一键启动，无报错。
2. 核心业务可用（列表、详情、增删改）。
3. 认证闭环：注册、登录、登出、受保护路由、会话失效。
4. 密码哈希、参数化 SQL、XSS 转义、cookie 标志到位。
5. 自动化测试覆盖认证关键路径并全部通过。
6. 无越界修改、无密钥入库、无未经授权的提交。

不达标就返工，返工单写清：位置、复现、当前结果、期望结果、复测命令。
