"""Single-flight local status reader. All disk parsing runs away from Tk callbacks."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from netshield.core.agent_status import read_snapshot


class SnapshotReader:
    def __init__(self, settings_path, loader=read_snapshot):
        self.settings_path = settings_path
        self.loader = loader
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='netshield-status')
        self.future = None
        self.closed = False
        self.cached = None
        self.signature = None

    def _signature(self):
        directory = Path(self.settings_path).parent
        signatures = []
        for name in ('agent-status.sqlite3', 'agent-status.sqlite3-wal', 'agent-status.json'):
            try:
                st = (directory / name).lstat()
                signatures.append((st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_uid))
            except FileNotFoundError:
                signatures.append(None)
        return tuple(signatures)

    def _read(self):
        try:
            before = self._signature()
            if self.cached is not None and before == self.signature:
                return self.cached
            result = self.loader(self.settings_path)
            after = self._signature()
            if before == after and result[1] is None:
                self.signature, self.cached = after, result
            else:
                self.signature, self.cached = None, None
            return result
        except Exception as exc:
            return {}, f'Ajan durumu okunamadı: {type(exc).__name__}'

    def request(self):
        if self.closed or self.future is not None:
            return False
        self.future = self.executor.submit(self._read)
        return True

    def poll(self):
        if self.future is None or not self.future.done():
            return None
        result = self.future.result()
        self.future = None
        return result

    def close(self):
        self.closed = True
        self.executor.shutdown(wait=False, cancel_futures=True)
