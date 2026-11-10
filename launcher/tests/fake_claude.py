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

Before any step it writes a record to `FAKE_CLAUDE_OUT`: its argv, working
folder, standard input, environment, the settings file's content, and the
state of the git work tree. The variables' names hold no word LR-28 removes.
"""

import json
import os
import subprocess
import sys
import time


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
        stdin_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["stdin_is_utf8"] = False
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(record, fh)

    result_text = "The fake model finished."
    exit_code = 0
    try:
        for step in steps:
            op = step["op"]
            if op == "commit":
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
        "session_id": "00000000-0000-4000-8000-000000000000",
    }
    sys.stdout.write(json.dumps(answer))
    sys.stdout.flush()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
