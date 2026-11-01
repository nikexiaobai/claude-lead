"""Codex桌面共享会话调度；项目内容仅来自UTF-8任务文件。"""
import argparse
from collections import deque
import hashlib
import importlib.metadata
import inspect
import json
import re
import shlex
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlparse

TERMINAL = {'completed', 'failed', 'interrupted'}
APPROVALS = {'item/commandExecution/requestApproval', 'item/fileChange/requestApproval'}
AUTO_SOURCE = 'mentor-auto-readonly'
SHELL_META = set(';|&<>`$()\r\n')
# 白名单只放能确定不改工作区的命令；其余一律留给用户决定。
READ_ONLY_COMMANDS = {
    'ls', 'pwd', 'cat', 'head', 'tail', 'wc', 'file', 'stat', 'du', 'df',
    'tree', 'nl', 'cut', 'sort', 'uniq', 'tr', 'basename', 'dirname',
    'realpath', 'readlink', 'echo', 'printf', 'date', 'uname', 'whoami',
    'id', 'diff', 'rg', 'grep', 'ag', 'which',
}
GIT_READ_SUBCOMMANDS = {
    'status', 'diff', 'log', 'show', 'blame', 'annotate', 'shortlog',
    'rev-parse', 'rev-list', 'ls-files', 'ls-tree', 'cat-file', 'describe',
    'diff-tree', 'diff-index', 'diff-files', 'whatchanged', 'reflog', 'grep',
    'merge-base', 'count-objects', 'var',
}
GIT_BRANCH_FLAGS = {'-l', '--list', '-a', '--all', '-r', '--remotes', '-v', '-vv',
                    '--show-current', '--contains', '--merged', '--no-merged',
                    '--points-at', '--format'}
FORBIDDEN_FIND = {'-delete', '-exec', '-execdir', '-ok', '-okdir',
                  '-fprint', '-fprint0', '-fprintf', '-fls'}
TEST_RUNNERS = {'pytest', 'jest', 'vitest', 'phpunit', 'rspec', 'mocha', 'tox'}
# 只读也会把内容送进对话记录，凭据类文件一律不自动放行。
SENSITIVE_NAMES = {'.env', '.netrc', '.npmrc', '.pypirc', '.git-credentials',
                   'credentials', 'credentials.json', 'auth.json',
                   'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'}
SENSITIVE_SUFFIXES = ('.pem', '.key', '.p12', '.pfx', '.keystore')
SENSITIVE_PARTS = ('/.ssh/', '/.aws/', '/.gnupg/', '/.codex/', '/.config/gh/')


def git_read_only(args):
    if not args:
        return False
    sub, rest = args[0], args[1:]
    if sub in GIT_READ_SUBCOMMANDS:
        return True
    if sub == 'branch':
        return all(a.startswith('-') and a.split('=')[0] in GIT_BRANCH_FLAGS for a in rest)
    if sub == 'tag':
        return not rest or rest[0] in ('-l', '--list', '-n')
    if sub == 'remote':
        return not rest or rest[0] in ('-v', '--verbose', 'show', 'get-url')
    if sub == 'stash':
        return rest[:1] in (['list'], ['show'])
    if sub == 'config':
        return bool(rest) and rest[0] in ('--get', '--get-all', '--get-regexp', '--list', '-l')
    if sub == 'worktree':
        return rest[:1] == ['list']
    if sub == 'submodule':
        return rest[:1] in (['status'], ['summary'])
    return False


def test_command(tokens):
    head, rest = tokens[0], tokens[1:]
    if head in TEST_RUNNERS:
        return True
    if head in ('npm', 'pnpm', 'yarn', 'bun') and rest:
        return rest[0] in ('test', 't') or (
            rest[0] == 'run' and len(rest) > 1 and rest[1].startswith('test'))
    if head in ('python', 'python3') and rest[:2] in (['-m', 'pytest'], ['-m', 'unittest']):
        return True
    if head == 'node' and rest[:1] == ['--test']:
        return True
    if head in ('go', 'cargo', 'mvn', 'gradle', 'dotnet', 'make') and rest[:1] in (
            ['test'], ['check']):
        return True
    return False


def sensitive_token(token):
    name = token.rsplit('/', 1)[-1].lower()
    return (name in SENSITIVE_NAMES or name.startswith('.env.')
            or name.endswith(SENSITIVE_SUFFIXES)
            or any(part in token.lower() for part in SENSITIVE_PARTS))


def read_only_command(command):
    if not command or len(command) > 2000 or any(c in command for c in SHELL_META):
        return False
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    if not tokens or '/' in tokens[0]:
        return False
    if any(t.startswith(('--output', '--to-file')) or sensitive_token(t) for t in tokens):
        return False
    head, args = tokens[0], tokens[1:]
    if head == 'git':
        return git_read_only(args)
    if head == 'find':
        return not any(a in FORBIDDEN_FIND for a in args)
    if head == 'diff':
        return not any(a in ('-o', '--output', '--to-file') for a in args)
    if head in ('sort', 'tree') and '-o' in args:
        return False
    if test_command(tokens):
        return True
    return head in READ_ONLY_COMMANDS


def auto_approval(event):
    """只读命令自动放行；其余返回 None，交给用户逐条决定。"""
    params = event.get('params') or {}
    if event.get('method') != 'item/commandExecution/requestApproval':
        return None
    if params.get('kind', 'command') != 'command' or params.get('networkApprovalContext'):
        return None
    actions = params.get('commandActions')
    if actions and any(a.get('type') not in ('read', 'listFiles', 'search') for a in actions):
        return None
    command = params.get('command')
    if not read_only_command(command):
        return None
    return {'decision': 'accept', 'reason': 'read-only allowlist: ' + command[:200]}


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def append_decision(run, record):
    with (run / 'decisions.jsonl').open('a', encoding='utf-8') as log:
        log.write(json.dumps(record, ensure_ascii=False) + '\n')


def write_json(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    temporary.replace(path)


def local_url(value):
    u = urlparse(value)
    if (u.scheme != 'ws' or u.hostname != '127.0.0.1' or not u.port
            or u.username or u.password or u.query or u.fragment or u.path not in ('', '/')):
        raise ValueError('仅允许无凭据的 ws://127.0.0.1:端口')
    return value


class ConnectionProblem(RuntimeError):
    def __init__(self, code, message, action):
        super().__init__(message)
        self.code = code
        self.action = action


def dependency_check():
    if sys.version_info < (3, 10):
        raise ConnectionProblem('PYTHON_UNSUPPORTED', '需要 Python 3.10 或更新版本',
                                '使用满足要求的现有Python解释器；不要自动安装')
    try:
        from websockets.sync.client import connect
        version = importlib.metadata.version('websockets')
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise ConnectionProblem('WEBSOCKETS_MISSING', '当前解释器缺少websockets同步客户端',
                                '使用已安装依赖的解释器，或先征得依赖安装授权') from error
    required = {'proxy', 'ping_interval', 'close_timeout', 'max_size'}
    if not required.issubset(inspect.signature(connect).parameters):
        raise ConnectionProblem('WEBSOCKETS_INCOMPATIBLE', 'websockets连接接口不兼容',
                                '核对已安装版本与当前接口，不在项目任务中临时升级依赖')
    return {'python': sys.version.split()[0], 'websockets': version}


def inspect_desktop(url):
    port = urlparse(local_url(url)).port
    if sys.platform == 'darwin':
        # ps provides the process tree; lsof identifies the process that owns
        # the established loopback connection to the shared app-server.
        processes_out = subprocess.run(
            ['ps', '-axo', 'pid=,ppid=,command='], capture_output=True,
            text=True, encoding='utf-8', check=True, timeout=30)
        socket_out = subprocess.run(
            ['lsof', '-nP', '-iTCP:' + str(port), '-FpnT'], capture_output=True,
            text=True, encoding='utf-8', check=False, timeout=30)
        processes = []
        for line in processes_out.stdout.splitlines():
            fields = line.strip().split(None, 2)
            if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
                processes.append({'ProcessId': int(fields[0]),
                                  'ParentProcessId': int(fields[1]),
                                  'Name': Path(fields[2].split()[0]).name,
                                  'ExecutablePath': fields[2]})
        connections, listeners = [], []
        pid, name = None, ''
        for line in socket_out.stdout.splitlines():
            if line.startswith('p'):
                pid = int(line[1:]) if line[1:].isdigit() else None
                name = ''
            elif line.startswith('n'):
                name = line[1:]
            elif line.startswith('TST=') and pid is not None:
                state = line[4:]
                if state == 'ESTABLISHED' and '->' in name:
                    ends = re.match(r'^(.+):(\d+)->(.+):(\d+)$', name)
                    if (ends and ends.group(1) in ('127.0.0.1', 'localhost', '[::1]')
                            and ends.group(3) in ('127.0.0.1', 'localhost', '[::1]')
                            and port in (int(ends.group(2)), int(ends.group(4)))):
                        connections.append({'OwningProcess': pid})
                elif state == 'LISTEN' and re.search(r':' + str(port) + r'$', name):
                    listeners.append({'LocalAddress': name, 'OwningProcess': pid})
        return {'processes': processes, 'connections': connections, 'listeners': listeners}

    script = (
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
        "$p=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath);"
        f"$c=@(Get-NetTCPConnection -RemotePort {port} -State Established -ErrorAction SilentlyContinue | "
        "Where-Object {$_.RemoteAddress -eq '127.0.0.1'} | Select-Object OwningProcess);"
        f"$l=@(Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,OwningProcess);"
        "@{processes=$p;connections=$c;listeners=$l}|ConvertTo-Json -Depth 4 -Compress"
    )
    out = subprocess.run(['powershell.exe', '-NoProfile', '-Command', script],
                         capture_output=True, text=True, encoding='utf-8', check=True, timeout=30)
    return json.loads(out.stdout)


def desktop_evidence(url):
    data = inspect_desktop(url)
    processes = {p['ProcessId']: p for p in data['processes']}
    desktops = {pid for pid, p in processes.items()
                if ((p['Name'].lower() in ('chatgpt.exe', 'codexdesktop.exe')
                     and 'codex' in (p.get('ExecutablePath') or '').lower())
                    or '/codex.app/contents/macos/' in
                    (p.get('ExecutablePath') or '').lower())}
    for connection in data['connections']:
        pid = connection['OwningProcess']
        seen = set()
        current = pid
        while current in processes and current not in seen:
            seen.add(current)
            if current in desktops:
                return {'desktopPid': current, 'connectionPid': pid, 'url': url}
            current = processes[current]['ParentProcessId']
    if not desktops:
        raise ConnectionProblem('DESKTOP_NOT_RUNNING', '未核实Codex桌面进程',
                                '先启动共享后端，再经授权启动桌面；此时不发送任务')
    raise ConnectionProblem('DESKTOP_NOT_SHARED', '未核实Codex桌面到共享端口的实际连接',
                            '桌面可能使用独立后端或尚未连上；保存工作后正常重连，不强杀')


def connection_report(url):
    local_url(url)
    checks = []
    try:
        dependencies = dependency_check()
        checks.append({'check': 'dependencies', 'ok': True, **dependencies})
    except ConnectionProblem as error:
        checks.append({'check': 'dependencies', 'ok': False, 'code': error.code,
                       'message': str(error), 'action': error.action})
    try:
        evidence = desktop_evidence(url)
        checks.append({'check': 'desktop', 'ok': True, **evidence})
    except Exception as error:
        checks.append({'check': 'desktop', 'ok': False,
                       'code': getattr(error, 'code', 'DESKTOP_INSPECTION_FAILED'),
                       'message': str(error),
                       'action': getattr(error, 'action', '核对桌面进程与TCP检查权限')})
    if checks[0]['ok']:
        rpc = None
        try:
            rpc = Rpc(url)
            checks.append({'check': 'backend', 'ok': True})
        except Exception as error:
            code = 'BACKEND_UNAVAILABLE' if isinstance(error, OSError) else 'BACKEND_PROTOCOL_FAILED'
            checks.append({'check': 'backend', 'ok': False, 'code': code,
                           'message': str(error),
                           'action': '核对共享后端监听/当前协议；不要改用独立CLI或重复派单'})
        finally:
            if rpc:
                rpc.close()
    else:
        checks.append({'check': 'backend', 'ok': False, 'code': 'DEPENDENCY_BLOCKED',
                       'action': '依赖未满足，不尝试后端连接'})
    ready = all(check['ok'] for check in checks)
    return {'status': 'connected' if ready else 'blocked', 'ready': ready,
            'url': url, 'checks': checks}



def final_message(turn):
    messages = [i for i in turn.get('items', []) if i.get('type') == 'agentMessage']
    final = [i for i in messages if i.get('phase') == 'final_answer']
    return (final or messages)[-1].get('text') if messages else None


class Rpc:
    auto_approve = False

    def __init__(self, url, run=None, thread=None, auto_approve=False):
        from websockets.sync.client import connect
        self.connection = connect(local_url(url), proxy=None, open_timeout=5,
                                  close_timeout=2, ping_interval=None,
                                  max_size=32 * 1024 * 1024)
        self.ws = self.connection.__enter__()
        self.run = run
        self.thread = thread
        self.auto_approve = auto_approve
        self.sequence = 0
        self.events = deque()
        try:
            self.info = self.call('initialize', {
                'clientInfo': {'name': 'desktop_mentor', 'version': '1.0'},
                'capabilities': {'experimentalApi': True}})
            self.ws.send(json.dumps({'method': 'initialized', 'params': {}}))
        except BaseException:
            self.close()
            raise

    def close(self):
        self.connection.__exit__(None, None, None)

    def receive(self, timeout):
        event = json.loads(self.ws.recv(timeout=timeout))
        if 'id' in event and 'method' in event:
            if (self.run is None or event['method'] not in APPROVALS
                    or event.get('params', {}).get('threadId') != self.thread):
                self.ws.send(json.dumps({'id': event['id'], 'error': {
                    'code': -32601, 'message': 'Unsupported approval; no permission granted'}}))
                raise RuntimeError('遇到未支持/不属于本任务的审批，未授予权限')
            digest = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
            request = self.run / ('approval-' + digest[:16] + '.json')
            answer = self.run / ('decision-' + digest[:16] + '.json')
            write_json(request, {'digest': digest, 'threadId': self.thread,
                                 'request': event, 'decisionFile': str(answer)})
            automatic = auto_approval(event) if self.auto_approve else None
            if automatic:
                append_decision(self.run, {'at': now(), 'digest': digest,
                                           'threadId': self.thread, 'method': event['method'],
                                           'source': AUTO_SOURCE, 'decision': automatic['decision'],
                                           'reason': automatic['reason']})
                self.ws.send(json.dumps({'id': event['id'],
                                         'result': {'decision': automatic['decision']}}))
                print(json.dumps({'event': 'approval_auto_accepted', 'file': str(request),
                                  'reason': automatic['reason']}, ensure_ascii=False), flush=True)
                return {'method': 'mentor/decisionRelayed', 'params': {'threadId': self.thread}}
            print(json.dumps({'event': 'approval_pending', 'file': str(request)}), flush=True)
            end = time.monotonic() + 3600
            while time.monotonic() < end:
                if answer.exists():
                    data = json.loads(answer.read_text(encoding='utf-8'))
                    if (data.get('digest') != digest or data.get('threadId') != self.thread
                            or data.get('source') != 'explicit-user-answer'
                            or data.get('decision') not in ('accept', 'decline', 'cancel')):
                        raise RuntimeError('审批决定身份或类型不匹配，不自动放行')
                    append_decision(self.run, {'at': now(), 'digest': digest,
                                               'threadId': self.thread, 'method': event['method'],
                                               'source': data['source'],
                                               'decision': data['decision'], 'reason': 'user'})
                    self.ws.send(json.dumps({'id': event['id'], 'result': {
                        'decision': data['decision']}}))
                    return {'method': 'mentor/decisionRelayed', 'params': {'threadId': self.thread}}
                threading.Event().wait(0.5)
            self.ws.send(json.dumps({'id': event['id'], 'result': {'decision': 'cancel'}}))
            raise TimeoutError('未收到用户决定，取消本请求，未授予权限')
        return event

    def call(self, method, params):
        self.sequence += 1
        key = self.sequence
        self.ws.send(json.dumps({'id': key, 'method': method, 'params': params}))
        end = time.monotonic() + 60
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('RPC超时：' + method)
            event = self.receive(remaining)
            if event.get('id') == key and 'method' not in event:
                if 'error' in event:
                    raise RuntimeError(method + ': ' + str(event['error']))
                return event.get('result')
            self.events.append(event)

    def read_thread(self):
        data = self.call('thread/read', {'threadId': self.thread, 'includeTurns': True})['thread']
        if data['id'] != self.thread:
            raise RuntimeError('返回会话与目标不符')
        return data

    def wait(self, turn_id, seconds):
        end = time.monotonic() + seconds
        with (self.run / 'events.jsonl').open('a', encoding='utf-8') as log:
            while time.monotonic() < end:
                event = self.events.popleft() if self.events else self.receive(end - time.monotonic())
                params = event.get('params', {})
                if params.get('threadId') != self.thread:
                    continue
                # 不复制命令输出/思考流到另一份日志；详细过程在桌面查看。
                summary = {'method': event.get('method'), 'threadId': self.thread,
                           'turnId': params.get('turnId')}
                log.write(json.dumps(summary) + '\n')
                log.flush()
                if (event.get('method') == 'turn/completed'
                        and params.get('turn', {}).get('id') == turn_id):
                    return params['turn']
        raise TimeoutError('等待结束；必须recover原回合，不重复发送任务')


def check_resume(thread, manifest, project):
    if str(Path(thread['cwd']).resolve()).casefold() != str(project).casefold():
        raise RuntimeError('会话项目目录不符')
    turns = thread.get('turns', [])
    if any(t.get('status') not in TERMINAL for t in turns):
        raise RuntimeError('存在运行中或未知回合，先recover，不重复派单')
    if manifest.get('phase') in ('starting', 'unknown', 'running'):
        raise RuntimeError('上次调用结果未核实，先recover')


def session_policy(data, project, mode):
    expected = {'read-only': 'readOnly', 'workspace-write': 'workspaceWrite'}[mode]
    sandbox = data.get('sandbox', {})
    roots = sandbox.get('writableRoots', [])
    if (data.get('approvalPolicy') != 'on-request'
            or data.get('approvalsReviewer') != 'user'
            or sandbox.get('type') != expected
            or sandbox.get('networkAccess', False) is not False
            or str(Path(data.get('cwd', '')).resolve()).casefold() != str(project).casefold()
            or any(str(Path(root).resolve()).casefold() != str(project).casefold() for root in roots)):
        raise RuntimeError('会话实际权限/审批/项目与请求不符，不发送项目消息；核对当前Schema与配置')
    return {'approvalPolicy': data['approvalPolicy'], 'approvalsReviewer': data['approvalsReviewer'],
            'sandboxType': sandbox['type'], 'cwd': data['cwd']}


def result_for(turn):
    return {'status': turn.get('status', 'unknown'), 'error': turn.get('error'),
            'finalMessage': final_message(turn)}


def send(args):
    task = Path(args.task).resolve()
    project = Path(args.project).resolve()
    prompt = Path(args.prompt).read_text(encoding='utf-8')
    if not project.is_dir() or not prompt.strip():
        raise ValueError('项目目录不存在或任务消息为空')
    dependency_check()
    evidence = desktop_evidence(args.url)
    task.mkdir(parents=True, exist_ok=True)
    manifest_path = task / 'task.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8')) if manifest_path.exists() else {}
    if manifest and (manifest['project'] != str(project) or manifest['mode'] != args.mode
                     or manifest['url'] != args.url):
        raise RuntimeError('项目/权限/连接与已记录任务不符，不隐式切换')
    # 每任务单一派单锁；崩溃遗留锁需检查原进程与回合后人工解除。
    lock = task / 'dispatch.lock'
    with lock.open('x', encoding='utf-8') as f:
        f.write(str(__import__('os').getpid()))
    rpc = None
    run = task / ('turn-' + uuid.uuid4().hex)
    try:
        run.mkdir()
        (run / 'request.md').write_text(prompt, encoding='utf-8')
        rpc = Rpc(args.url, run=run, thread=manifest.get('threadId'),
                  auto_approve=args.auto_approve == 'readonly')
        if manifest:
            check_resume(rpc.read_thread(), manifest, project)
            data = rpc.call('thread/resume', {'threadId': rpc.thread, 'cwd': str(project),
                                             'sandbox': args.mode, 'approvalPolicy': 'on-request',
                                             'approvalsReviewer': 'user'})
        else:
            data = rpc.call('thread/start', {'cwd': str(project), 'sandbox': args.mode,
                                            'approvalPolicy': 'on-request',
                                            'approvalsReviewer': 'user'})
            rpc.thread = data['thread']['id']
            manifest = {'project': str(project), 'mode': args.mode, 'url': args.url,
                        'threadId': rpc.thread, 'phase': 'ready', 'run': str(run)}
            write_json(manifest_path, manifest)
            # 同一连接创建和启动；无rollout的新会话不能跨连接resume。
        manifest['effectivePolicy'] = session_policy(data, project, args.mode)
        manifest.pop('turnId', None)
        manifest.update({'phase': 'starting', 'run': str(run), 'desktopEvidence': evidence})
        write_json(manifest_path, manifest)
        data = rpc.call('turn/start', {'threadId': rpc.thread, 'input': [
            {'type': 'text', 'text': prompt, 'text_elements': []}]})
        manifest.update({'phase': 'running', 'turnId': data['turn']['id']})
        write_json(manifest_path, manifest)
        write_json(run / 'state.json', manifest)
        print(json.dumps({'event': 'turn_started', 'run': str(run),
                          'threadId': rpc.thread, 'turnId': manifest['turnId']}), flush=True)
        # 仅负责发送；状态读取和后续处理必须由用户明确“继续”后触发。
    except Exception as error:
        write_json(run / 'dispatch-error.json', {'status': 'unknown', 'error': str(error)})
        if manifest.get('phase') in ('starting', 'running'):
            manifest['phase'] = 'unknown'
            write_json(manifest_path, manifest)
        raise
    finally:
        try:
            if rpc:
                rpc.close()
        finally:
            lock.unlink(missing_ok=True)


def recover(args):
    path = Path(args.task).resolve() / 'task.json'
    manifest = json.loads(path.read_text(encoding='utf-8'))
    run = Path(manifest['run'])
    rpc = Rpc(manifest['url'], run=run, thread=manifest['threadId'],
              auto_approve=args.auto_approve == 'readonly')
    try:
        thread = rpc.read_thread()
        turns = thread.get('turns', [])
        turn_id = manifest.get('turnId')
        # turn/start应答丢失时仅展示候选历史，不能猜测最新回合就是本次。
        turn = next((t for t in turns if t['id'] == turn_id), None) if manifest['phase'] != 'starting' else None
        if args.relay and turn and turn.get('status') not in TERMINAL:
            # 单次阻塞等待，不轮询；期间只读命令自动放行，其余等待用户决定。
            try:
                turn = rpc.wait(turn_id, args.relay)
            except TimeoutError as error:
                print(json.dumps({'event': 'relay_timeout', 'detail': str(error)},
                                 ensure_ascii=False), flush=True)
                turns = rpc.read_thread().get('turns', [])
                turn = next((t for t in turns if t['id'] == turn_id), turn)
        result = result_for(turn) if turn else {'status': 'unknown', 'turnIds': [t['id'] for t in turns]}
        write_json(run / 'recovery.json', result)
        if turn and result['status'] in TERMINAL:
            manifest['phase'] = result['status']
            write_json(path, manifest)
        print(json.dumps(result, ensure_ascii=False))
    finally:
        rpc.close()


def watch(args):
    run = Path(args.run)
    seen = set()
    end = time.monotonic() + args.seconds
    while time.monotonic() < end:
        for path in run.glob('approval-*.json'):
            if path.name not in seen:
                data = json.loads(path.read_text(encoding='utf-8'))
                if not Path(data['decisionFile']).exists():
                    print(json.dumps({'event': 'approval_pending', 'file': str(path)}), flush=True)
                seen.add(path.name)
        for name in ('result.json', 'recovery.json', 'dispatch-error.json'):
            path = run / name
            if path.exists():
                print(json.dumps({'event': name, 'file': str(path)}), flush=True)
                return
        threading.Event().wait(1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    d = sub.add_parser('doctor')
    d.add_argument('--url', default='ws://127.0.0.1:18765')
    backend = sub.add_parser('backend')
    backend.add_argument('--url', default='ws://127.0.0.1:18765')
    server = sub.add_parser('serve')
    server.add_argument('--codex', required=True)
    server.add_argument('--url', default='ws://127.0.0.1:18765')
    s = sub.add_parser('send')
    s.add_argument('--url', default='ws://127.0.0.1:18765')
    for name in ('task', 'project', 'prompt'):
        s.add_argument('--' + name, required=True)
    s.add_argument('--mode', choices=('read-only', 'workspace-write'), required=True)
    s.add_argument('--auto-approve', choices=('readonly', 'none'), default='readonly')
    r = sub.add_parser('recover')
    r.add_argument('--task', required=True)
    r.add_argument('--auto-approve', choices=('readonly', 'none'), default='readonly')
    r.add_argument('--relay', type=int, default=0)
    w = sub.add_parser('watch')
    w.add_argument('--run', required=True)
    w.add_argument('--seconds', type=int, default=1750)
    args = p.parse_args()
    if args.command == 'serve':
        exe = Path(args.codex).resolve()
        if not exe.is_file():
            raise ValueError('Codex可执行文件不存在')
        subprocess.run([str(exe), '-c', 'analytics.enabled=false', '-c',
                        'features.code_mode_host=true', 'app-server', '--listen',
                        local_url(args.url)], check=True)
    elif args.command == 'backend':
        dependencies = dependency_check()
        rpc = Rpc(args.url)
        rpc.close()
        print(json.dumps({'status': 'backendReady', **dependencies}))
    elif args.command == 'doctor':
        report = connection_report(args.url)
        print(json.dumps(report, ensure_ascii=False))
        if not report['ready']:
            raise SystemExit(1)
    elif args.command == 'send':
        send(args)
    elif args.command == 'recover':
        recover(args)
    else:
        watch(args)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
