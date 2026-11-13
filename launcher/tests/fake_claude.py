"""A fake `claude` for the launcher's tests (standard library only).

It is started by the launcher as `claude_command` + the model's arguments,
with the prompt on standard input and `<run>/repo` as its working folder.

`FAKE_CLAUDE_MODE` holds a JSON list of steps to perform, in order:

  {"op": "commit", "path": P, "text": T}            write P and commit it
  {"op": "commit_as", "path": P, "name": N, "email": E}   commit as another author
  {"op": "commit_committer_as", "path": P, "name": N, "email": E}
  {"op": "write", "path": P, "text": T}             write P, do not commit
  {"op": "proposal", "text": T}                     write .gate-security-proposal.md
  {"op": "switch", "branch": B}                     git switch -c B
  {"op": "detach"}                                  git checkout --detach
  {"op": "orphan_reset"}                            reset the branch to an unrelated commit
  {"op": "touch", "file": F}                        create file F (a flag for the fake API)
  {"op": "push_race", "remote": R, "ref": REF, "record": F, "force": B}
                                                    push an unrelated commit to R's REF, write its sha to F
  {"op": "sleep", "seconds": S, "pids": F}          start a sleeping child, write both pids to F, sleep
  {"op": "exit", "code": N}                         stop here with exit code N
  {"op": "result", "text": T}                       the `result` text of the JSON output

Stage A (LR-51): with `--output-format stream-json` on its command line it writes
a stream instead of one JSON object, one event per line, flushed at once: a
`system/init` event first, then what the steps below emit, and a `result` event
last (with `num_turns`), unless a step says otherwise. Stream steps:

  {"op": "assistant", "id": I, "tools": [T, ...], "text": X, "parent": P}
                     an `assistant` event; without "id" (or with null) it has no
                     message.id; "raw_id" puts any JSON value there instead; one
                     `tool_use` block per id in "tools"; "parent" is its
                     parent_tool_use_id (a subagent's message), null by default
  {"op": "tool_result", "ids": [T, ...]}            a `user` event with those tool results
  {"op": "line", "text": X}                         a raw line, as is (not JSON, for instance);
                                                    with "hex" instead, those bytes
  {"op": "snapshot", "src": F, "dst": G}            copy the file F to G as it is now
  {"op": "big_line", "bytes": N}                    one line of N bytes
  {"op": "event", "event": E}                       any JSON value as one line
  {"op": "api_retry", "error": C}                   a `system/api_retry` event with that category
  {"op": "burst", "count": N, "prefix": X, "tools": B}
                     N messages written at once, ids X-1 ... X-N, each with one
                     tool_use (and its result) when B is true
  {"op": "forever", "interval": S, "prefix": X}     messages with tool use and results, every S
                     seconds, never ending by itself (it ignores --max-turns)
  {"op": "ignore_break"}                            ignore CTRL_BREAK (SIGBREAK) and SIGINT
  {"op": "spawn_family", "pids": F}                 start a hidden-window child (CREATE_NO_WINDOW)
                     and a grandchild whose parent has already exited, both
                     sleeping 300 s; write the pids to F
  {"op": "marker", "file": F}                       write the file F (a sign of progress)
  {"op": "pause", "seconds": S}                     sleep S seconds, no child
  {"op": "crash", "code": N}                        end at once with exit code N, no result event
  {"op": "no_result"}                               end normally but write no result event

Before any step it writes a record to `FAKE_CLAUDE_OUT`: its argv, working
folder, standard input, environment, the settings file's content, and the
state of the git work tree. The variables' names hold no word LR-28 removes.
"""

import json
import os
import signal
import subprocess
import sys
import time

SESSION = "00000000-0000-4000-8000-000000000000"
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW: what Node's spawn sets with windowsHide


def streaming():
    argv = sys.argv
    return any(a == "--output-format" and i + 1 < len(argv) and argv[i + 1] == "stream-json"
               for i, a in enumerate(argv))


def emit_raw(data):
    sys.stdout.buffer.write(data + b"\n")
    sys.stdout.buffer.flush()


def emit(event):
    emit_raw(json.dumps(event).encode("utf-8"))


def assistant_event(step):
    content = []
    if step.get("text", "Working.") is not None:
        content.append({"type": "text", "text": step.get("text", "Working.")})
    for tool_id in step.get("tools", []):
        content.append({"type": "tool_use", "id": tool_id, "name": "Bash", "input": {"command": "git status"}})
    message = {"type": "message", "role": "assistant", "model": "fake", "content": content}
    if "raw_id" in step:
        message["id"] = step["raw_id"]
    elif step.get("id") is not None:
        message["id"] = step["id"]
    return {"type": "assistant", "message": message, "parent_tool_use_id": step.get("parent"),
            "session_id": SESSION}


def tool_result_event(ids):
    return {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": i, "content": "ok"} for i in ids]},
        "parent_tool_use_id": None, "session_id": SESSION}


def job_facts():
    """Windows: whether this process is in a job, and that job's limit flags (LR-58)."""
    if os.name != "nt":
        return None, None
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    in_job = wintypes.BOOL()
    k32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    if not k32.IsProcessInJob(k32.GetCurrentProcess(), None, ctypes.byref(in_job)):
        return None, None

    class Basic(ctypes.Structure):
        _fields_ = [("a", ctypes.c_int64), ("b", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                    ("c", ctypes.c_size_t), ("d", ctypes.c_size_t), ("e", wintypes.DWORD),
                    ("f", ctypes.c_size_t), ("g", wintypes.DWORD), ("h", wintypes.DWORD)]

    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", ctypes.c_uint64 * 6), ("m", ctypes.c_size_t * 4)]

    info = Extended()
    k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                              ctypes.c_void_p]
    flags = None
    if in_job.value and k32.QueryInformationJobObject(None, 9, ctypes.byref(info), ctypes.sizeof(info), None):
        flags = int(info.basic.LimitFlags)
    return bool(in_job.value), flags


def spawn_family(pids_path):
    sleeper = "import time; time.sleep(300)"
    flags = NO_WINDOW if os.name == "nt" else 0
    hidden = subprocess.Popen([sys.executable, "-c", sleeper], creationflags=flags)
    grandchild_file = pids_path + ".grandchild"
    middle = subprocess.Popen([sys.executable, "-c",
                               "import subprocess, sys; p = subprocess.Popen([sys.executable, '-c', "
                               f"{sleeper!r}], creationflags={flags}); "
                               "open(sys.argv[1], 'w').write(str(p.pid))", grandchild_file])
    middle.wait(timeout=60)
    with open(grandchild_file, encoding="utf-8") as fh:
        grandchild = int(fh.read().strip())
    with open(pids_path, "w", encoding="utf-8") as fh:
        json.dump({"model": os.getpid(), "hidden_child": hidden.pid, "middle": middle.pid,
                   "grandchild": grandchild}, fh)


def git(*args, env=None, check=True):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=check, env=env)


def git_out(*args):
    res = git(*args, check=False)
    return res.stdout.strip() if res.returncode == 0 else None


def git_all_local(name):
    """The local values of a setting, as a list; None when it is not set."""
    res = git("config", "--local", "--get-all", name, check=False)
    if res.returncode != 0:
        return None
    return res.stdout.split("\n")[:-1]


def read_git_file(*parts):
    git_dir = git_out("rev-parse", "--git-dir")
    if git_dir is None:
        return None
    try:
        with open(os.path.join(git_dir, *parts), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def work_tree_files():
    found = []
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            found.append(os.path.relpath(os.path.join(root, name), ".").replace("\\", "/"))
    return sorted(found)


def write_file(path, text):
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with open(path, "a" if os.path.exists(path) else "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def main():
    out_path = os.environ.get("FAKE_CLAUDE_OUT")
    steps = json.loads(os.environ.get("FAKE_CLAUDE_MODE") or "[]")
    stdin_bytes = sys.stdin.buffer.read()
    settings_text = None
    if "--settings" in sys.argv:
        i = sys.argv.index("--settings")
        if i + 1 < len(sys.argv):
            try:
                with open(sys.argv[i + 1], "rb") as fh:
                    settings_text = fh.read().decode("utf-8", "replace")
            except OSError as exc:
                settings_text = f"<unreadable: {exc}>"
    record = {
        "argv": sys.argv,
        "cwd": os.getcwd(),
        "stdin": stdin_bytes.decode("utf-8", "replace"),
        "stdin_is_utf8": True,
        "env": dict(os.environ),
        "settings": settings_text,
        "pid": os.getpid(),
        "git": {
            "branch": git_out("symbolic-ref", "--short", "-q", "HEAD"),
            "head": git_out("rev-parse", "HEAD"),
            "count": git_out("rev-list", "--count", "HEAD"),
            "shallow": git_out("rev-parse", "--is-shallow-repository"),
            "status": git_out("status", "--porcelain"),
            "user_name": git_out("config", "--get", "user.name"),
            "user_email": git_out("config", "--get", "user.email"),
            "remote_url": git_out("config", "--get", "remote.origin.url"),
            "credential_helpers": git_all_local("credential.helper"),
            "exclude": read_git_file("info", "exclude"),
            "local_config": read_git_file("config"),
        },
        "files": work_tree_files(),
        "started": time.time(),
    }
    try:
        record["in_job"], record["job_limit_flags"] = job_facts()
    except Exception as exc:  # noqa: BLE001  # reason: a harness probe must not stop the fake
        record["in_job"], record["job_limit_flags"] = None, f"<probe failed: {exc!r}>"
    try:
        stdin_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["stdin_is_utf8"] = False
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(record, fh)

    result_text = "The fake model finished."
    exit_code = 0
    stream = streaming()
    write_result = True
    if stream:
        emit({"type": "system", "subtype": "init", "session_id": SESSION, "model": "fake", "tools": []})
    try:
        for step in steps:
            op = step["op"]
            if op == "assistant":
                emit(assistant_event(step))
            elif op == "tool_result":
                emit(tool_result_event(step["ids"]))
            elif op == "line":
                emit_raw(bytes.fromhex(step["hex"]) if "hex" in step else step["text"].encode("utf-8"))
            elif op == "snapshot":
                with open(step["src"], "rb") as src, open(step["dst"], "wb") as dst:
                    dst.write(src.read())
            elif op == "big_line":
                emit_raw(b"x" * int(step["bytes"]))
            elif op == "event":
                emit(step["event"])
            elif op == "api_retry":
                emit({"type": "system", "subtype": "api_retry", "attempt": 1, "max_retries": 10,
                      "retry_delay_ms": 500, "error_status": 429, "error": step["error"],
                      "session_id": SESSION})
            elif op == "burst":
                prefix = step.get("prefix", "burst")
                lines = []
                for n in range(1, int(step["count"]) + 1):
                    tools = [f"tu-{prefix}-{n}"] if step.get("tools") else []
                    lines.append(json.dumps(assistant_event({"id": f"{prefix}-{n}", "tools": tools})))
                    if tools:
                        lines.append(json.dumps(tool_result_event(tools)))
                emit_raw("\n".join(lines).encode("utf-8"))
            elif op == "forever":
                prefix = step.get("prefix", "loop")
                n = 0
                while True:
                    n += 1
                    emit(assistant_event({"id": f"{prefix}-{n}", "tools": [f"tu-{prefix}-{n}"]}))
                    emit(tool_result_event([f"tu-{prefix}-{n}"]))
                    time.sleep(float(step.get("interval", 0.05)))
            elif op == "ignore_break":
                if hasattr(signal, "SIGBREAK"):
                    signal.signal(signal.SIGBREAK, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
            elif op == "spawn_family":
                spawn_family(step["pids"])
            elif op == "marker":
                with open(step["file"], "w", encoding="utf-8") as fh:
                    fh.write(f"{time.time()}\n")
            elif op == "pause":
                time.sleep(float(step["seconds"]))
            elif op == "crash":
                sys.stdout.flush()
                os._exit(int(step.get("code", 3)))
            elif op == "no_result":
                write_result = False
            elif op == "commit":
                write_file(step["path"], step.get("text", "print('hello')\n"))
                git("add", "--", step["path"])
                git("commit", "-q", "-m", step.get("message", f"Add {step['path']}"))
            elif op == "commit_as":
                write_file(step["path"], step.get("text", "x = 1\n"))
                git("add", "--", step["path"])
                git("-c", f"user.name={step['name']}", "-c", f"user.email={step['email']}",
                    "commit", "-q", "-m", f"Add {step['path']}")
            elif op == "commit_committer_as":
                write_file(step["path"], step.get("text", "x = 2\n"))
                git("add", "--", step["path"])
                env = dict(os.environ)
                env["GIT_COMMITTER_NAME"] = step["name"]
                env["GIT_COMMITTER_EMAIL"] = step["email"]
                git("commit", "-q", "-m", f"Add {step['path']}", env=env)
            elif op == "write":
                write_file(step["path"], step.get("text", "left = True\n"))
            elif op == "proposal":
                with open(".gate-security-proposal.md", "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(step["text"])
            elif op == "switch":
                git("switch", "-q", "-c", step["branch"])
            elif op == "detach":
                git("checkout", "-q", "--detach")
            elif op == "orphan_reset":
                tree = git("write-tree").stdout.strip()
                commit = git("commit-tree", tree, "-m", "unrelated").stdout.strip()
                git("reset", "-q", "--hard", commit)
            elif op == "touch":
                with open(step["file"], "w", encoding="utf-8") as fh:
                    fh.write("moved\n")
            elif op == "push_race":
                tree = git("write-tree").stdout.strip()
                commit = git("commit-tree", tree, "-m", "a racing commit").stdout.strip()
                plus = "+" if step.get("force") else ""
                git("push", "-q", step["remote"], f"{plus}{commit}:{step['ref']}")
                with open(step["record"], "w", encoding="utf-8") as fh:
                    fh.write(commit)
            elif op == "sleep":
                child = subprocess.Popen([sys.executable, "-c",
                                          f"import time; time.sleep({float(step['seconds'])})"])
                with open(step["pids"], "w", encoding="utf-8") as fh:
                    json.dump({"model": os.getpid(), "child": child.pid}, fh)
                time.sleep(float(step["seconds"]))
            elif op == "exit":
                exit_code = int(step["code"])
                break
            elif op == "result":
                result_text = step["text"]
            else:
                raise SystemExit(f"fake claude: unknown step {op!r}")

    except (subprocess.CalledProcessError, OSError, KeyError, ValueError) as exc:
        # The harness failed, not the model: say so where the tests look.
        detail = getattr(exc, "stderr", "") or ""
        if out_path:
            with open(out_path + ".error", "w", encoding="utf-8") as fh:
                fh.write(f"step {step!r} failed: {exc!r} {detail}")
        return 97

    answer = {
        "type": "result",
        "subtype": "success" if exit_code == 0 else "error_during_execution",
        "is_error": exit_code != 0,
        "num_turns": 13,
        "duration_ms": 98765,
        "duration_api_ms": 87654,
        "total_cost_usd": 0.4321,
        "result": result_text,
        "session_id": SESSION,
    }
    if stream:
        if write_result:
            emit(answer)
        return exit_code
    sys.stdout.write(json.dumps(answer))
    sys.stdout.flush()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
