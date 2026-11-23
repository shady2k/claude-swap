"""Synthetic admitted launch workers with real supervision and pipe barriers.

Auth status is a local deterministic response, not Claude build evidence.
No network socket is allowed. Real handoffs exec the pinned synthetic script.
Transparent routing requires a prepared profile; session routing starts cold.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[1]

class Child:
    def __init__(self, stand, name, mode, barrier=False, scan_pid=None):
        self.log = stand.directory / (name + '.events')
        self.log.write_text('')
        reader, writer = os.pipe()
        commands, command_writer = os.pipe()
        scope_commands, self.scope_writer = os.pipe()
        self.reader, self.writer = reader, command_writer
        env = stand.env | {'ADMISSION_LOG': str(self.log), 'ADMISSION_EVENTS': str(writer),
                           'ADMISSION_COMMANDS': str(commands), 'ADMISSION_SCOPE_COMMANDS': str(scope_commands), 'ADMISSION_BARRIER': str(int(barrier)),
                           'ADMISSION_SCAN_PID': str(scan_pid or ''), 'ADMISSION_MODE': mode}
        self.process = subprocess.Popen([sys.executable, '-I', '-c',
            f"import sys; sys.path.insert(0, {str(PROJECT)!r}); from tests.profile_admission_stand import worker; worker()",
            mode, stand.route], env=env, cwd=stand.directory,
            pass_fds=(writer, commands, scope_commands), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        os.close(writer)
        os.close(commands)
        os.close(scope_commands)
        self.pending = b''
    def event(self, expected):
        while b'\n' not in self.pending:
            assert select.select([self.reader], [], [], 15)[0], self.log.read_text()
            data = os.read(self.reader, 4096)
            assert data, (self.process.poll(), self.log.read_text(), self.process.stderr.read())
            self.pending += data
        line, self.pending = self.pending.split(b'\n', 1)
        assert line.decode() == expected, (line, self.log.read_text())
    def send(self, command):
        os.write(self.writer, (command + '\n').encode())
    def send_scope(self, command):
        os.write(self.scope_writer, (command + "\n").encode())
    def finish(self):
        output, errors = self.process.communicate(timeout=20)
        self.output, self.errors = output, errors
        assert self.process.returncode in (0, 3, 4, 7), (output, errors, self.log.read_text())
        return self.process.returncode
    def counts(self):
        lines = self.log.read_text().splitlines()
        return {key: lines.count(key) for key in ('launch', 'post', 'probe')}
    def close(self):
        if self.process.poll() is None:
            try:
                self.send('exit')
            except BrokenPipeError:
                pass
            self.process.terminate()
            self.process.communicate(timeout=10)
        os.close(self.reader)
        os.close(self.writer)
        os.close(self.scope_writer)

class AdmissionStand:
    def __init__(self, directory, route, *, warm=False, disabled=False):
        self.directory, self.route, self.children = directory, route, []
        self.env = {k:v for k,v in os.environ.items() if not (k.upper().endswith('_PROXY') or k.startswith('CLAUDE_') or k.startswith('ANTHROPIC_') or k == 'XDG_DATA_HOME')}
        self.env.update(HOME=str(directory/'home'), XDG_DATA_HOME=str(directory/'home/data'),
            CLAUDE_SWAP_TEST_MODE='1', CLAUDE_SWAP_TEST_ENDPOINT='https://admission.example',
            ANTHROPIC_BASE_URL='https://admission.example', HTTPS_PROXY='http://127.0.0.1:18080',
            ADMISSION_ROOT=str(directory), ADMISSION_WARM=str(int(warm)),
            ADMISSION_DISABLED=str(int(disabled)))
        self.binary = directory/'bin/claude'
        self.binary.parent.mkdir()
        self.binary.write_text(f'#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(PROJECT)!r})\nfrom tests.profile_admission_stand import synthetic\nsynthetic()\n')
        self.binary.chmod(0o700)
        self.env.update(PATH=str(self.binary.parent)+':/usr/bin:/bin', CLAUDE_SWAP_TEST_CLAUDE_ALLOW=str(self.binary))
        child = self.launch('seed', mode='seed')
        assert child.finish() == 0, child.errors
        self.backup = directory/'home/data/claude-swap'
    def __enter__(self): return self
    def __exit__(self, *args):
        for child in self.children: child.close()
    @property
    def profile(self):
        from claude_swap.session import session_dir_for
        return session_dir_for(self.backup, '2', 'target@example.test')
    def launch(self, name, barrier=False, mode='launch', scan_pid=None):
        child = Child(self, name, mode, barrier, scan_pid)
        self.children.append(child)
        return child
    def snapshot(self):
        result = {}
        for folder in ('credentials', 'configs', 'sessions'):
            directory = self.backup / folder
            for path in (directory, *directory.rglob('*')):
                if not os.path.lexists(path):
                    continue
                info = path.lstat()
                content = os.readlink(path) if path.is_symlink() else (
                    path.read_bytes() if path.is_file() else None
                )
                result[str(path.relative_to(self.backup))] = (info.st_ino, info.st_mode, content)
        return result
    def switch(self): return self.launch('switch', mode='switch').finish()
    def free(self): return self.launch('free', mode='free').finish() == 0

def emit(event):
    with open(os.environ['ADMISSION_LOG'], 'a') as stream: stream.write(event+'\n')
    os.write(int(os.environ['ADMISSION_EVENTS']), (event+'\n').encode())

def command(expected, *, scope=False):
    value = b''
    while not value.endswith(b'\n'):
        key = 'ADMISSION_SCOPE_COMMANDS' if scope else 'ADMISSION_COMMANDS'
        chunk = os.read(int(os.environ[key]), 1)
        assert chunk, 'controller disconnected'
        value += chunk
    assert value.decode().strip() == expected

def synthetic():
    def deny(event, args):
        if event in ('socket.connect', 'socket.getaddrinfo', 'socket.__new__'):
            raise RuntimeError('network denied')
    sys.addaudithook(deny)
    import signal
    # Every synthetic tree has a finite life, including on a failed assertion.
    signal.alarm(12)
    if os.environ['ADMISSION_MODE'].startswith('signal-'):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            signal.signal(sig, signal.SIG_IGN)
    emit('launch')
    if os.environ['ADMISSION_MODE'] == 'signal-live':
        emit('live')
        command('exit')
        os._exit(7)
    # The direct exec exits, leaving its detached child supervised.
    if os.fork(): os._exit(7 if os.environ['ADMISSION_MODE'] == 'release-contention' or os.environ['ADMISSION_MODE'].startswith('signal-') else 0)
    os.setsid()
    signal.alarm(12)
    Path(os.environ['ADMISSION_LOG'] + '.pid').write_text(str(os.getpid()))
    emit('live')
    command('exit')
    os._exit(0)

def worker():
    from types import SimpleNamespace
    from claude_swap import session, transparent, profile_ownership as own, real_claude, paths, launch_policy
    from claude_swap.switcher import ClaudeAccountSwitcher
    from claude_swap.exceptions import ClaudeSwitchError
    def deny(event, args):
        if event in ('socket.connect', 'socket.getaddrinfo', 'socket.__new__'):
            emit('post')
            raise RuntimeError('network denied')
    sys.addaudithook(deny)
    mode, route = sys.argv[1:]
    switcher = ClaudeAccountSwitcher()
    root = switcher.backup_dir
    profile = session.session_dir_for(root, '2', 'target@example.test')
    if mode == 'seed':
        switcher._setup_directories()
        accounts = {str(n): {'email': email, 'uuid':f'uuid-{n}', 'organizationUuid':f'org-{n}'}
                    for n,email in ((1,'default@example.test'),(2,'target@example.test'))}
        switcher._write_json(switcher.sequence_file, {'activeAccountNumber':1, 'sequence':[1,2], 'accounts':accounts})
        for n, account in accounts.items():
            credentials = json.dumps({'claudeAiOauth':{'accessToken':'synthetic-'+n, 'expiresAt':9999999999999}})
            config = json.dumps({'oauthAccount':{'emailAddress':account['email'], 'organizationUuid':account['organizationUuid'], 'accountUuid':account['uuid']}})
            switcher._write_account_credentials(n, account['email'], credentials)
            switcher._write_account_config(n, account['email'], config)
            if n == '1':
                paths.get_global_config_path().write_text(config)
                paths.get_claude_config_home().mkdir(parents=True, exist_ok=True)
                (paths.get_claude_config_home()/".credentials.json").write_text(credentials)
        if route == 'transparent' or os.environ['ADMISSION_WARM'] == '1':
            profile.mkdir(parents=True)
            (profile/'.claude.json').write_text(switcher.read_account_config('2','target@example.test'))
            (profile/'.credentials.json').write_text(switcher.read_account_credentials('2','target@example.test'))
            transparent.enable(root, accept_shared_history=True, pool=['2'])
            if os.environ['ADMISSION_DISABLED'] == '1':
                transparent.disable(root)
        return
    if mode == 'recipient':
        data = switcher._get_sequence_data()
        data['accounts']['2']['uuid'] = 'replacement-uuid'
        switcher._write_json(switcher.sequence_file, data)
        return
    if mode == 'identity':
        paths.get_global_config_path().write_text(switcher.read_account_config('2','target@example.test'))
        return
    if mode == 'free':
        with own.ownership_lock(root):
            if own.profile_busy_locked(root, '2', profile):
                raise SystemExit(4)
        return
    if mode == 'switch':
        try: switcher.switch_to('2')
        except ClaudeSwitchError as exc:
            print(type(exc).__name__, file=sys.stderr)
            raise SystemExit(4)
        return
    if scan_pid := os.environ.get('ADMISSION_SCAN_PID'):
        from claude_swap import process_detection
        original_alive = process_detection.is_pid_alive
        scanned = False
        def alive(pid):
            nonlocal scanned
            if pid == int(scan_pid) and not scanned:
                scanned = True
                emit('pid-read-barrier')
                command('continue')
                emit('pid-read-resumed')
            return original_alive(pid)
        process_detection.is_pid_alive = alive
    if mode in ('journal-error', 'journal-lock-error'):
        from claude_swap.exceptions import LockError
        def journal(*args):
            if mode == 'journal-lock-error':
                raise LockError('synthetic journal lock contention')
            raise OSError('synthetic journal write failure')
        transparent._journal = journal
    if mode == 'capability-refusal':
        import errno
        from claude_swap import spawn
        def refuse(*args, **kwargs):
            raise OSError(errno.ENOSYS, 'synthetic pidfd capability unavailable')
        spawn.os.pidfd_open = refuse
    if mode == 'generation-publication':
        original_mark = own.mark_running_locked
        def generation_mark(backup, launch_id, *args, **kwargs):
            own.invalidate_generation_locked(backup, profile)
            return original_mark(backup, launch_id, *args, **kwargs)
        own.mark_running_locked = generation_mark
    if mode == 'signal-publication':
        original_mark = own.mark_running_locked
        def publication(*args, **kwargs):
            result = original_mark(*args, **kwargs)
            emit('publication')
            command('continue')
            return result
        own.mark_running_locked = publication
    if mode == 'signal-before-fork':
        from claude_swap import spawn
        original_fork = spawn.os.fork
        def before_fork():
            emit('before-fork')
            command('continue')
            return original_fork()
        spawn.os.fork = before_fork
    if mode in ('signal-after-reap', 'unknown-wait'):
        from claude_swap import spawn
        original_wait = spawn.os.waitpid
        paused_reap = False
        def after_reap(*args):
            nonlocal paused_reap
            if mode == 'unknown-wait' and paused_reap:
                import errno
                raise OSError(errno.EIO, 'synthetic unknown wait')
            result = original_wait(*args)
            if not paused_reap:
                paused_reap = True
                if mode != 'unknown-wait':
                    emit('after-reap')
                    command('continue', scope=True)
            return result
        spawn.os.waitpid = after_reap
    if mode == 'signal-release':
        original_completed = own.release_completed
        def real_release(root, launch_id):
            emit('release-wait')
            command('release')
            emit('release-attempt')
            return original_completed(root, launch_id)
        own.release_completed = real_release
    if mode == 'release-contention':
        original_completed = own.release_completed
        def release_completed(root, launch_id):
            lock = own.ownership_lock(root)
            acquire = lock.acquire
            attempted = False
            def contend(timeout=None):
                nonlocal attempted
                if not attempted:
                    attempted = True
                    emit('release-wait')
                    command('release')
                    return False
                return acquire(timeout)
            lock.acquire = contend
            try:
                return original_completed(root, launch_id)
            finally:
                lock.acquire = acquire
        own.release_completed = release_completed
    original = own.reserve_locked
    def reserve(*args, **kwargs):
        record = original(*args, **kwargs)
        if os.environ['ADMISSION_BARRIER'] == '1':
            emit('reserved')
            # Wait outside the physical locks, via the validity/profile hook.
        return record
    own.reserve_locked = reserve
    paused = False
    def barrier():
        nonlocal paused
        if not paused and os.environ['ADMISSION_BARRIER'] == '1':
            paused = True
            command('continue')
    original_valid = session.SessionManager._is_session_valid
    def valid(self, *args, **kwargs):
        barrier()
        return original_valid(self, *args, **kwargs)
    session.SessionManager._is_session_valid = valid
    original_profile = transparent._profile_dir
    def profile_dir(*args):
        barrier()
        return original_profile(*args)
    transparent._profile_dir = profile_dir
    def probe(self, *args, **kwargs):
        emit('probe')
        return SimpleNamespace(returncode=0, stdout=json.dumps({'loggedIn':mode != 'invalid','authMethod':'claude.ai','email':'target@example.test','orgId':'org-2'}))
    real_claude.RealClaude.run = probe
    try:
        if route == 'session': session.SessionManager(switcher).run('2', ['-p','synthetic prompt'], share=False, share_history=False)
        else:
            directory = paths.get_shim_dir(root)
            transparent._launch(transparent._invocation_marker(directory, False), ['-p','synthetic prompt'], root)
    except (ClaudeSwitchError, OSError) as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        raise SystemExit(4)
