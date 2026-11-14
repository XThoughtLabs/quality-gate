"""LR-98: the operator's command, `xtl_operator.py` (HQ-TASK-M1-C2 amendment 2, tests o to u), on a stand-in for
Windows; written before the program. Each test is marked LR-98.

The stand-in gives the operator's and the executor's SIDs, the folder's security, the process table, the witness
(which writes its file in the test's folder) and Windows' runas (which prints, as the real one does, the user's and the
computer's names). Every SID and name here is a stand-in; nothing is started for real."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from operator_kit import ADMINS_SID, FULL, OP_SID, READ_EXECUTE, SECOND, SYSTEM_SID, WITNESS_FORMAT

EXEC_SID = "S-1-5-21-1111111111-2222222222-3333333333-1007"
EXEC_NAME = "exec-zz-user"
COMPUTER = "PC-ZZ-0451"
PASSWORD = "pw-zz-never-seen"
ANY_SID = re.compile(r"S-1-\d+(-\d+)+")
LAUNCHER_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def xo():
    import xtl_operator
    return xtl_operator


class FakeWitnessProcess:
    def __init__(self, win, argv):
        self.win, self.argv, self.pid = win, argv, 7000
        self.stopped = False

    def poll(self):
        return 0 if self.stopped else None

    def stop(self):
        self.stopped = True
        self.win.events.append("witness stopped")


class FakeWindows:
    """The machine as the operator's command sees it. `phases` drives what the process table shows over time."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.now_value = 5_000 * SECOND
        self.events: list[str] = []
        self.folder_state = None              # missing
        self.make_ok = True
        self.set_ok = True
        self.repair_to = "right"              # what set_acl leaves
        self.witness_writes = True
        self.witness_proc: FakeWitnessProcess | None = None
        self.runas_calls: list[tuple[str, str]] = []
        self.runas_code = 0
        self.runas_output = (f"Enter the password for {EXEC_NAME}: \r\n"
                             f"Attempting to start cmd as user \"{COMPUTER}\\{EXEC_NAME}\" ...\r\n").encode()
        self.launcher_polls = 3               # polls while the launcher lives
        self.launcher_found = True
        self.interrupt_after = None
        self.polls = 0
        self.elevated_value = False
        self.witness_age = 0                  # how old the witness's first write is
        self.witness_delay = 0                # seconds the clock moves on after the witness's one write
        self.decoy = False                    # a process started after runas by someone else, listed first
        self.ancestor_states: dict = {}       # the folders above the witness's folder, by path

    # identities
    def own_sid(self):
        return OP_SID

    def elevated(self):
        return self.elevated_value

    def account_sid(self, name):
        return EXEC_SID if name == EXEC_NAME else None

    # the folder, and the folders above it (by default: like a drive's root, safe)
    def folder(self, path):
        if Path(path) == self.tmp / "witness":
            return self.folder_state
        return self.ancestor_states.get(str(Path(path)), SAFE_ANCESTOR)

    def make_folder(self, path, owner, aces):
        self.events.append(f"make_folder {owner} {sorted(aces)}")
        if self.make_ok:
            Path(path).mkdir(parents=True, exist_ok=True)
            self.folder_state = (owner, list(aces), True, False, True)
        return self.make_ok

    def set_acl(self, path, aces):
        self.events.append(f"set_acl {sorted(aces)}")
        if not self.set_ok:
            return False
        if self.repair_to == "right":
            owner = self.folder_state[0]
            self.folder_state = (owner, list(aces), True, False, True)
        return True

    # time and processes
    def now(self):
        return self.now_value

    def sleep(self, seconds):
        self.now_value += int(seconds * SECOND)
        if self.interrupt_after is not None:
            self.interrupt_after -= 1
            if self.interrupt_after < 0:
                raise KeyboardInterrupt

    def own_process(self):
        return 6000, 4_000 * SECOND

    def processes(self):
        self.polls += 1
        table = {6000: {"ppid": 1, "image": "python.exe", "created": 4_000 * SECOND, "session": 1}}
        if self.runas_calls and self.decoy:
            table[7900] = {"ppid": 1, "image": "cmd.exe", "created": 5_001 * SECOND, "session": 1}
            if self.polls <= 1:
                table[7904] = {"ppid": 7900, "image": "python.exe", "created": 5_002 * SECOND, "session": 1}
        if self.runas_calls and self.launcher_found:
            table[8000] = {"ppid": 7500, "image": "cmd.exe", "created": 5_001 * SECOND, "session": 1}
            if self.launcher_polls > 0:
                self.launcher_polls -= 1
                table[8004] = {"ppid": 8000, "image": "python.exe", "created": 5_002 * SECOND, "session": 1}
        return table

    # the witness and runas
    def start_witness(self, argv):
        self.events.append("witness started")
        self.witness_proc = FakeWitnessProcess(self, argv)
        path = Path(argv[argv.index("--file") + 1])
        if self.witness_writes:
            path.write_text(json.dumps({"format": WITNESS_FORMAT, "started": self.now_value,
                                        "written": self.now_value + SECOND // 4 - self.witness_age,
                                        "pairs": []}), encoding="utf-8")
        self.now_value += int(self.witness_delay * SECOND)
        return self.witness_proc

    def runas(self, user, command):
        self.events.append("runas")
        self.runas_calls.append((user, command))
        return self.runas_code, self.runas_output, 7500, 5_000 * SECOND


def config(tmp_path: Path, **override) -> Path:
    values = {"witness_file": str(tmp_path / "witness" / "witness.json"), "windows_user": EXEC_NAME,
              "launcher_python": r"C:\Users\exec-zz-user\xtl-launcher-venv\Scripts\python.exe",
              "key_file": r"C:\keys\never-read.pem", "runs_dir": r"C:\Users\exec-zz-user\xtl-runs"}
    values.update(override)
    path = tmp_path / "launcher.toml"
    path.write_text("[launcher]\n" + "".join(f"{k} = '{v}'\n" for k, v in values.items()), encoding="utf-8")
    return path


def run(xo, win, tmp_path, *argv, cfg=None):
    out = io.StringIO()
    operator = xo.Operator(win, out.write, LAUNCHER_DIR)
    code = operator.main(["--config", str(cfg or config(tmp_path)), *argv])
    return code, out.getvalue()


SAFE_ANCESTOR = ("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                 [("S-1-5-11", 0x4, "Allow"), (SYSTEM_SID, FULL, "Allow"), (ADMINS_SID, FULL, "Allow")], False, False, True)
RIGHT = [(OP_SID, FULL, "Allow"), (SYSTEM_SID, FULL, "Allow"), (ADMINS_SID, FULL, "Allow"),
         (EXEC_SID, READ_EXECUTE, "Allow")]


# ---------------------------------------------------------------- o: a missing folder is created right
@pytest.mark.lr(98)
def test_lr98_o_a_missing_folder_is_created_with_the_right_permissions(xo, tmp_path):
    win = FakeWindows(tmp_path)
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 0, out
    made = [e for e in win.events if e.startswith("make_folder")]
    assert made == [f"make_folder {OP_SID} {sorted(RIGHT)}"]
    assert win.events.index(made[0]) < win.events.index("witness started") < win.events.index("runas")


# ---------------------------------------------------------------- p: wrong permissions repaired, or a stop
@pytest.mark.lr(98)
def test_lr98_p_a_folder_with_wrong_permissions_is_repaired(xo, tmp_path):
    win = FakeWindows(tmp_path)
    (tmp_path / "witness").mkdir()
    win.folder_state = (OP_SID, RIGHT + [(EXEC_SID, 0x2, "Allow")], False, False, True)
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 0, out
    assert f"set_acl {sorted(RIGHT)}" in win.events
    assert "runas" in win.events


@pytest.mark.lr(98)
@pytest.mark.parametrize("flaw", ["set refused", "still wrong after the repair", "owned by the executor",
                                  "a junction", "not a folder", "creation refused"])
def test_lr98_p_a_folder_that_cannot_be_made_right_stops_and_nothing_starts(xo, tmp_path, flaw):
    win = FakeWindows(tmp_path)
    wrong = RIGHT + [(EXEC_SID, 0x40000, "Allow")]
    if flaw == "creation refused":
        win.make_ok = False
    else:
        (tmp_path / "witness").mkdir()
        win.folder_state = {"set refused": (OP_SID, wrong, False, False, True),
                            "still wrong after the repair": (OP_SID, wrong, False, False, True),
                            "owned by the executor": (EXEC_SID, RIGHT, True, False, True),
                            "a junction": (OP_SID, RIGHT, True, True, True),
                            "not a folder": (OP_SID, RIGHT, True, False, False)}[flaw]
        win.set_ok = flaw != "set refused"
        win.repair_to = "unchanged" if flaw == "still wrong after the repair" else "right"
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1, out
    assert "witness started" not in win.events and "runas" not in win.events
    assert "nothing was started" in out.lower()
    if flaw == "owned by the executor":
        assert not any(e.startswith("set_acl") for e in win.events), "another user's folder was changed"


# ---------------------------------------------------------------- q: no fresh write, nothing starts
@pytest.mark.lr(98)
def test_lr98_q_without_a_fresh_write_the_witness_is_stopped_and_nothing_starts(xo, tmp_path):
    win = FakeWindows(tmp_path)
    win.witness_writes = False
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1, out
    assert win.witness_proc is not None and win.witness_proc.stopped
    assert "runas" not in win.events


@pytest.mark.lr(98)
def test_lr98_q_an_old_file_from_an_earlier_witness_is_not_a_fresh_write(xo, tmp_path):
    win = FakeWindows(tmp_path)
    win.witness_writes = False
    folder = tmp_path / "witness"
    folder.mkdir()
    win.folder_state = (OP_SID, RIGHT, True, False, True)
    (folder / "witness.json").write_text(json.dumps({"format": WITNESS_FORMAT, "started": 1, "written": win.now_value,
                                                     "pairs": []}), encoding="utf-8")
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1 and "runas" not in win.events, out


# ---------------------------------------------------------------- r: the run's end stops the witness
@pytest.mark.lr(98)
def test_lr98_r_the_runs_end_stops_the_witness(xo, tmp_path):
    win = FakeWindows(tmp_path)
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 0, out
    assert win.witness_proc.stopped
    assert win.events[-1] == "witness stopped"
    assert "the run has ended" in out


@pytest.mark.lr(98)
def test_lr98_r_a_forged_early_end_only_stops_the_witness(xo, tmp_path):
    """The launcher's process vanishes at once (an early end): the witness is stopped and nothing else happens; the
    launcher, if it still ran, would then find no fresh witness and use the old rules (LR-97's freshness check)."""
    win = FakeWindows(tmp_path)
    win.launcher_polls = 1  # found once, gone at the next look
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert win.witness_proc.stopped
    assert win.events.count("runas") == 1 and win.events.count("witness started") == 1


@pytest.mark.lr(98)
def test_lr98_r_when_the_launchers_process_is_not_found_the_witness_lives_to_its_lifetime(xo, tmp_path):
    win = FakeWindows(tmp_path)
    win.launcher_found = False
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert win.witness_proc.stopped  # at the witness's lifetime, not before
    lifetime = int(win.witness_proc.argv[win.witness_proc.argv.index("--lifetime-seconds") + 1])
    assert win.now_value - 5_000 * SECOND >= lifetime * SECOND


@pytest.mark.lr(98)
def test_lr98_a_refused_password_stops_the_witness_and_says_so_without_names(xo, tmp_path):
    win = FakeWindows(tmp_path)
    win.runas_code = 1
    win.runas_output = (f"Enter the password for {EXEC_NAME}: \r\nAttempting to start cmd as user "
                        f"\"{COMPUTER}\\{EXEC_NAME}\" ...\r\nRUNAS ERROR: Unable to run - cmd\r\n"
                        "1326: The user name or password is incorrect.\r\n").encode()
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1 and win.witness_proc.stopped, out
    assert "1326" in out and EXEC_NAME not in out and COMPUTER not in out


# ---------------------------------------------------------------- s: Ctrl+C and the lifetime
@pytest.mark.lr(98)
def test_lr98_s_ctrl_c_stops_the_witness(xo, tmp_path):
    win = FakeWindows(tmp_path)
    win.launcher_polls = 10_000
    win.interrupt_after = 5
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code != 0
    assert win.witness_proc.stopped
    assert "old rules" in out


@pytest.mark.lr(98)
@pytest.mark.parametrize("argv, minutes", [(("task", "--issue", "1"), 89), (("fix", "--pr", "4"), 89),
                                           (("spec", "--slug", "s1"), 89), (("preflight",), 10),
                                           (("watch", "--minutes", "15"), 20)])
def test_lr98_s_the_witness_has_a_lifetime_and_knows_its_parent(xo, tmp_path, argv, minutes):
    win = FakeWindows(tmp_path)
    run(xo, win, tmp_path, *argv)
    a = win.witness_proc.argv
    assert int(a[a.index("--lifetime-seconds") + 1]) == minutes * 60
    assert a[a.index("--parent") + 1] == f"6000:{4_000 * SECOND}"
    assert Path(a[a.index("--file") + 1]) == tmp_path / "witness" / "witness.json"
    assert Path(a[a.index("-I") + 1]).name == "xtl_witness.py"


# ---------------------------------------------------------------- the launcher's command through runas
@pytest.mark.lr(98)
@pytest.mark.parametrize("argv, tail", [(("task", "--issue", "1"), "task --issue 1"),
                                        (("task", "--issue", "2", "--max-messages", "3"), "task --issue 2 --max-messages 3"),
                                        (("fix", "--pr", "4"), "fix --pr 4"), (("spec", "--slug", "s1"), "spec --slug s1"),
                                        (("preflight",), "check"), (("watch", "--minutes", "15"), "watch --minutes 15")])
def test_lr98_the_launcher_starts_as_the_executor_through_runas(xo, tmp_path, argv, tail):
    win = FakeWindows(tmp_path)
    cfg = config(tmp_path)
    run(xo, win, tmp_path, *argv, cfg=cfg)
    (user, command), = win.runas_calls
    assert user == EXEC_NAME
    assert r"C:\Users\exec-zz-user\xtl-launcher-venv\Scripts\python.exe" in command
    assert str(LAUNCHER_DIR / "xtl_launcher.py") in command and str(cfg) in command
    assert f" {tail} " in command and command.rstrip('"').endswith("pause")
    assert "savecred" not in command.lower() and PASSWORD not in command


@pytest.mark.lr(98)
@pytest.mark.parametrize("key, value", [("launcher_python", r"C:\a&b\python.exe"), ("launcher_python", "python.exe"),
                                        ("witness_file", "witness.json"), ("windows_user", "a/b"),
                                        ("windows_user", "")])
def test_lr98_a_bad_configuration_stops_before_anything(xo, tmp_path, key, value):
    win = FakeWindows(tmp_path)
    code, out = run(xo, win, tmp_path, "task", "--issue", "1", cfg=config(tmp_path, **{key: value}))
    assert code == 2, out
    assert win.events == []


@pytest.mark.lr(98)
def test_lr98_an_unknown_executor_user_or_an_elevated_window_stops(xo, tmp_path):
    win = FakeWindows(tmp_path)
    code, out = run(xo, win, tmp_path, "task", "--issue", "1", cfg=config(tmp_path, windows_user="nobody-zz"))
    assert code == 1 and win.events == [], out
    win = FakeWindows(tmp_path)
    win.elevated_value = True
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1 and win.events == [], out
    win = FakeWindows(tmp_path)
    win.account_sid = lambda name: OP_SID  # the executor's user named is the operator's own
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1 and win.events == [], out


# ---------------------------------------------------------------- t: nothing personal is printed
@pytest.mark.lr(98)
@pytest.mark.parametrize("argv", [("task", "--issue", "1"), ("preflight",), ("watch", "--minutes", "1")])
def test_lr98_t_no_password_name_or_sid_in_the_output(xo, tmp_path, argv):
    win = FakeWindows(tmp_path)
    code, out = run(xo, win, tmp_path, *argv)
    assert code == 0, out
    for secret in (PASSWORD, EXEC_NAME, COMPUTER):
        assert secret not in out
    assert not ANY_SID.search(out)
    assert re.search(r"\d{2}:\d{2}:\d{2}", out), "the output gives no time"
    folder = tmp_path / "witness"
    for path in folder.iterdir():
        assert not ANY_SID.search(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- u: no stored credential anywhere
@pytest.mark.lr(98)
@pytest.mark.parametrize("name", ["xtl_operator.py", "xtl_witness.py", "xtl_launcher.py"])
def test_lr98_u_no_savecred_and_no_credential_storage_in_the_code(name):
    text = (LAUNCHER_DIR / name).read_text(encoding="utf-8").lower()
    for word in ("savecred", "credwrite", "credentialmanager", "keyring", "getpass"):
        assert word not in text, f"{word} appears in {name}"
    if name != "xtl_launcher.py":  # the launcher runs cmdkey /list only to refuse a stored git credential (LR-7)
        for word in ("cmdkey", "credread", "input("):
            assert word not in text, f"{word} appears in {name}"


@pytest.mark.lr(98)
@pytest.mark.parametrize("name", ["xtl_operator.py", "xtl_witness.py"])
def test_lr98_the_programs_hold_no_user_name_sid_or_computer_name(name):
    import os
    text = (LAUNCHER_DIR / name).read_text(encoding="utf-8")
    well_known = ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
    for sid in well_known:  # SYSTEM, Administrators, TrustedInstaller: the same on every Windows
        text = text.replace(sid, "")
    assert not ANY_SID.search(text)
    # the pilot's executor users, and the names of whoever runs the tests, read at run time and never written here
    names = ["mp-claude", "mp-codex"] + [os.environ.get(v, "") for v in ("USERNAME", "COMPUTERNAME")]
    names.append(Path(os.environ.get("USERPROFILE", "")).name)
    for word in (n.strip().lower() for n in names if n and n.strip()):
        assert word not in text.lower(), "a user or computer name appears in the program"
    assert "C:\\xtl" not in text and "C:\\\\xtl" not in text

@pytest.mark.lr(98)
@pytest.mark.parametrize("flaw", ["inheriting", "executor may write", "executor cannot read", "users may write",
                                  "null access list"])
def test_lr98_p_each_wrong_folder_state_is_repaired(xo, tmp_path, flaw):
    win = FakeWindows(tmp_path)
    (tmp_path / "witness").mkdir()
    rules = {"inheriting": RIGHT, "executor may write": RIGHT[:3] + [(EXEC_SID, FULL, "Allow")],
             "executor cannot read": RIGHT[:3], "users may write": RIGHT + [("S-1-5-32-545", 0x2, "Allow")],
             "null access list": None}[flaw]
    win.folder_state = (OP_SID, rules, flaw != "inheriting", False, True)
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 0, out
    assert f"set_acl {sorted(RIGHT)}" in win.events


@pytest.mark.lr(98)
def test_lr98_a_right_folder_is_left_as_it_is(xo, tmp_path):
    win = FakeWindows(tmp_path)
    (tmp_path / "witness").mkdir()
    win.folder_state = (OP_SID, RIGHT, True, False, True)
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 0, out
    assert not any(e.startswith(("set_acl", "make_folder")) for e in win.events)


@pytest.mark.lr(98)
@pytest.mark.parametrize("age_seconds, delay_seconds", [(2.5, 0), (30, 0), (0, 2.5), (0, 3)])
def test_lr98_q_a_stale_first_write_is_not_fresh_and_the_wait_is_five_seconds(xo, tmp_path, age_seconds,
                                                                             delay_seconds):
    """A first write older than 2 s when it is read (written long ago, or written once and then nothing more while
    the clock moved on) is not fresh; the wait ends at 5 s."""
    win = FakeWindows(tmp_path)
    win.witness_age = int(age_seconds * SECOND)
    win.witness_delay = delay_seconds
    start = win.now_value
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1 and "runas" not in win.events and win.witness_proc.stopped, out
    assert win.now_value - start <= int(5.2 * SECOND)


@pytest.mark.lr(98)
def test_lr98_r_a_new_process_that_is_not_the_runas_windows_child_is_not_taken_for_the_launcher(xo, tmp_path):
    win = FakeWindows(tmp_path)
    win.decoy = True  # a process started after runas by someone else, listed first, with a child that ends at once
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 0, out
    assert win.polls >= 4, "the witness was stopped when the decoy's child ended, before the launcher's end"