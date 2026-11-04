"""An in-memory stand-in for the Git-data routes of CONTRACTS.md section 9 (gate.archive --api-repo).

It behaves like GitHub where the contract depends on it: a commit made through the API is signed and authored by
`github-actions[bot]` only when its body holds exactly `message`, `tree` and `parents` (W-13); moving a branch without
`force` needs a fast-forward, otherwise 422; creating a branch that exists is 422. Tests can seed commits written by
another actor, make the next moves fail, let a competing commit land in the middle of a write, and so on.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

BOT = "github-actions[bot]"
DEFAULT_REPO = "example-org/example-app"
DEFAULT_TOKEN = "SENTINEL-VALUE-GATETOKEN"


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def blob_sha(data: bytes) -> str:
    return _sha1(b"blob %d\0" % len(data) + data)


class FakeGitApi:
    def __init__(self, stub, repo: str = DEFAULT_REPO, token: str = DEFAULT_TOKEN, *, ignore_case: bool = False,
                 require_auth: bool = True):
        self.stub, self.repo, self.token = stub, repo, token
        self.ignore_case = ignore_case   # GitHub treats OWNER/NAME without regard to letter case
        self.require_auth = require_auth # False: a public repository, read without any credential (gate.reproduce takes none)
        self.blobs: dict[str, bytes] = {}
        self.trees: dict[str, dict[str, tuple[str, str, str]]] = {}   # tree id -> {path: (mode, type, blob sha)}
        self.commits: dict[str, dict] = {}                              # commit sha -> {tree, parents, author, verified, n}
        self.branches: dict[str, str] = {}
        self._n = 0
        # what the gate sent
        self.blob_bodies: list = []
        self.tree_bodies: list = []
        self.commit_bodies: list = []
        self.moves: list[dict] = []                                      # {"method", "branch", "body", "status"}
        self.bad_auth: list[str] = []
        # behaviour switches
        self.new_author = BOT           # the author GitHub gives a commit made through the API
        self.sign_new = True            # whether GitHub signs it
        self.fail_moves: list[int] = [] # statuses to answer the next moves with, nothing changed
        self.interfere: list[dict] = [] # files of a competing commit that lands before the next move is judged
        self.commits_status = 200       # the status of GET .../commits
        self.one_commit_status = 200    # the status of GET .../commits/{sha}
        self.truncated = False          # the tree listing says it is truncated
        self.tamper_after_move = False  # after the first successful move, the branch silently changes a stored file
        self._tampered = False
        self._register()

    # ------------------------------------------------------------------ seeding and reading, for the tests
    def _new_commit(self, tree_id, parents, message, author, verified) -> str:
        self._n += 1
        sha = _sha1(json.dumps([tree_id, parents, message, self._n]).encode())
        self.commits[sha] = {"tree": tree_id, "parents": list(parents), "message": message, "author": author,
                             "verified": verified, "n": self._n}
        return sha

    def _put_tree(self, flat) -> str:
        tree_id = _sha1(json.dumps(sorted((p, *v) for p, v in flat.items())).encode())
        self.trees[tree_id] = dict(flat)
        return tree_id

    def head(self, branch: str = "reports"):
        return self.branches.get(branch)

    def flat_files(self, commit_sha: str) -> dict[str, str]:
        return {p: v[2] for p, v in self.trees[self.commits[commit_sha]["tree"]].items()}

    def files(self, branch: str = "reports") -> dict[str, bytes] | None:
        head = self.head(branch)
        if head is None:
            return None
        return {p: self.blobs[sha] for p, sha in self.flat_files(head).items()}

    def seed(self, files: dict[str, bytes], *, author: str = BOT, verified: bool = True, branch: str = "reports",
             message: str = "seed", delete=(), extra_parents=()) -> str:
        head = self.branches.get(branch)
        flat = dict(self.trees[self.commits[head]["tree"]]) if head else {}
        for path in delete:
            flat.pop(path)
        for path, data in files.items():
            sha = blob_sha(data)
            self.blobs[sha] = data
            flat[path] = ("100644", "blob", sha)
        parents = ([head] if head else []) + list(extra_parents)
        sha = self._new_commit(self._put_tree(flat), parents, message, author, verified)
        self.branches[branch] = sha
        return sha

    def mirror(self, commits, *, branch: str = "reports", foreign=None) -> None:
        """Show the API a branch that real git holds. `commits` is [(sha, [parent shas])], oldest first; `foreign` maps a
        sha to (author login, verified) for the commits that were not made by the bot."""
        empty = self._put_tree({})
        for sha, parents in commits:
            author, verified = (foreign or {}).get(sha, (BOT, True))
            self._n += 1
            self.commits[sha] = {"tree": empty, "parents": list(parents), "message": "mirrored", "author": author,
                                 "verified": verified, "n": self._n}
        self.branches[branch] = commits[-1][0]

    def reachable(self, branch: str = "reports") -> list[str]:
        head, seen, stack = self.branches.get(branch), set(), []
        if head:
            stack.append(head)
        while stack:
            sha = stack.pop()
            if sha in seen:
                continue
            seen.add(sha)
            stack.extend(self.commits[sha]["parents"])
        return sorted(seen, key=lambda s: -self.commits[s]["n"])

    def _descends(self, new: str, old: str) -> bool:
        seen, stack = set(), [new]
        while stack:
            sha = stack.pop()
            if sha == old:
                return True
            if sha in seen or sha not in self.commits:
                continue
            seen.add(sha)
            stack.extend(self.commits[sha]["parents"])
        return False

    # ------------------------------------------------------------------ the routes
    def _auth(self, req) -> bool:
        if not self.require_auth:
            return True
        ok = self.token in req.header("authorization")
        if not ok:
            self.bad_auth.append(f"{req.method} {req.path}")
        return ok

    def _register(self):
        s, base = self.stub, "/repos/" + re.escape(self.repo)
        if self.ignore_case:
            base = f"(?i:{base})"

        def guarded(fn):
            def handler(req):
                if not self._auth(req):
                    return 401, {"message": "Bad credentials"}
                return fn(req)
            return handler

        s.route("GET", base + r"/git/ref/heads/.+", guarded(self._get_ref))
        s.route("GET", base + r"/git/trees/[0-9a-f]+", guarded(self._get_tree))
        s.route("POST", base + r"/git/blobs", guarded(self._post_blob))
        s.route("GET", base + r"/git/blobs/[0-9a-f]+", guarded(self._get_blob))
        s.route("POST", base + r"/git/trees", guarded(self._post_tree))
        s.route("POST", base + r"/git/commits", guarded(self._post_commit))
        s.route("PATCH", base + r"/git/refs/heads/.+", guarded(self._patch_ref))
        s.route("POST", base + r"/git/refs", guarded(self._post_ref))
        s.route("GET", base + r"/commits", guarded(self._get_commits))
        s.route("GET", base + r"/commits/[0-9a-f]+", guarded(self._get_commit))

    def _get_ref(self, req):
        branch = req.path.split("/git/ref/heads/", 1)[1]
        sha = self.branches.get(branch)
        if sha is None:
            return 404, {"message": "Not Found"}
        return 200, {"ref": f"refs/heads/{branch}", "object": {"sha": sha, "type": "commit"}}

    def _get_tree(self, req):
        ident = req.path.rsplit("/", 1)[1]
        tree_id = self.commits[ident]["tree"] if ident in self.commits else ident
        if tree_id not in self.trees:
            return 404, {"message": "Not Found"}
        entries = [{"path": p, "mode": m, "type": t, "sha": sha, "size": len(self.blobs.get(sha, b""))}
                   for p, (m, t, sha) in sorted(self.trees[tree_id].items())]
        return 200, {"sha": tree_id, "tree": entries, "truncated": self.truncated}

    def _post_blob(self, req):
        body = req.json()
        self.blob_bodies.append(body)
        if body.get("encoding") == "base64":
            data = base64.b64decode(body["content"])
        else:
            data = body["content"].encode("utf-8")
        sha = blob_sha(data)
        self.blobs[sha] = data
        return 201, {"sha": sha}

    def _get_blob(self, req):
        sha = req.path.rsplit("/", 1)[1]
        if sha not in self.blobs:
            return 404, {"message": "Not Found"}
        raw = base64.b64encode(self.blobs[sha]).decode()
        wrapped = "\n".join(raw[i:i + 60] for i in range(0, len(raw), 60)) + ("\n" if raw else "")
        return 200, {"sha": sha, "encoding": "base64", "content": wrapped, "size": len(self.blobs[sha])}

    def _post_tree(self, req):
        body = req.json()
        self.tree_bodies.append(body)
        base_tree = body.get("base_tree")
        if base_tree is not None and base_tree not in self.trees:
            return 422, {"message": "base_tree does not exist"}
        flat = dict(self.trees[base_tree]) if base_tree else {}
        for entry in body["tree"]:
            path, sha = entry["path"], entry.get("sha")
            if sha is None:
                flat.pop(path, None)
            elif entry.get("type") == "tree":
                for sub, value in self.trees[sha].items():
                    flat[f"{path}/{sub}"] = value
            else:
                if sha not in self.blobs:
                    return 422, {"message": "tree.sha is not a known blob"}
                flat[path] = (entry.get("mode", "100644"), "blob", sha)
        return 201, {"sha": self._put_tree(flat)}

    def _post_commit(self, req):
        body = req.json()
        self.commit_bodies.append(body)
        if body["tree"] not in self.trees or any(p not in self.commits for p in body["parents"]):
            return 422, {"message": "tree or parent does not exist"}
        # GitHub signs a commit only when it chooses author and committer itself (W-13)
        clean = set(body) <= {"message", "tree", "parents"}
        sha = self._new_commit(body["tree"], body["parents"], body["message"],
                               self.new_author if clean else "someone-else",
                               bool(self.sign_new and clean))
        return 201, {"sha": sha}

    def _before_move(self):
        if self.fail_moves:
            return self.fail_moves.pop(0), {"message": "simulated failure"}
        if self.interfere:
            spec = self.interfere.pop(0)
            self.seed(spec["files"], author=spec.get("author", BOT), verified=spec.get("verified", True),
                      branch=spec.get("branch", "reports"), message="competing commit")
        return None

    def _after_move(self, branch):
        if self.tamper_after_move and not self._tampered:
            self._tampered = True
            head = self.branches[branch]
            target = next(p for p in self.flat_files(head) if p.endswith("/context.json"))
            self.seed({target: b'{"tampered": true}\n'}, branch=branch, message="tamper")

    def _patch_ref(self, req):
        branch = req.path.split("/git/refs/heads/", 1)[1]
        body = req.json()
        record = {"method": "PATCH", "branch": branch, "body": body, "status": None}
        self.moves.append(record)
        early = self._before_move()
        if early:
            record["status"] = early[0]
            return early
        if branch not in self.branches:
            record["status"] = 404
            return 404, {"message": "Reference does not exist"}
        new = body.get("sha")
        if new not in self.commits:
            record["status"] = 422
            return 422, {"message": "Object does not exist"}
        if not body.get("force") and not self._descends(new, self.branches[branch]):
            record["status"] = 422
            return 422, {"message": "Update is not a fast forward"}
        self.branches[branch] = new
        record["status"] = 200
        self._after_move(branch)
        return 200, {"ref": f"refs/heads/{branch}", "object": {"sha": new, "type": "commit"}}

    def _post_ref(self, req):
        body = req.json()
        branch = body["ref"].replace("refs/heads/", "", 1)
        record = {"method": "POST", "branch": branch, "body": body, "status": None}
        self.moves.append(record)
        early = self._before_move()
        if early:
            record["status"] = early[0]
            return early
        if branch in self.branches:
            record["status"] = 422
            return 422, {"message": "Reference already exists"}
        if body.get("sha") not in self.commits:
            record["status"] = 422
            return 422, {"message": "Object does not exist"}
        self.branches[branch] = body["sha"]
        record["status"] = 201
        self._after_move(branch)
        return 201, {"ref": body["ref"], "object": {"sha": body["sha"], "type": "commit"}}

    def _get_commits(self, req):
        if self.commits_status != 200:
            return self.commits_status, {"message": "simulated failure"}
        branch = req.q("sha") or "reports"
        per_page, page = int(req.q("per_page") or 30), int(req.q("page") or 1)
        shas = self.reachable(branch)[(page - 1) * per_page: page * per_page]
        return 200, [{"sha": sha, "author": {"login": self.commits[sha]["author"]},
                      "commit": {"verification": {"verified": self.commits[sha]["verified"]}}} for sha in shas]

    def _get_commit(self, req):
        """One commit: its parents and the files it changed against its first parent."""
        if self.one_commit_status != 200:
            return self.one_commit_status, {"message": "simulated failure"}
        sha = req.path.rsplit("/", 1)[1]
        if sha not in self.commits:
            return 404, {"message": "Not Found"}
        c = self.commits[sha]
        new = self.trees[c["tree"]]
        old = self.trees[self.commits[c["parents"][0]]["tree"]] if c["parents"] else {}
        files = []
        for path in sorted(set(new) | set(old)):
            if path not in old:
                files.append({"filename": path, "status": "added"})
            elif path not in new:
                files.append({"filename": path, "status": "removed"})
            elif new[path] != old[path]:
                files.append({"filename": path, "status": "modified"})
        per_page, page = int(req.q("per_page") or 30), int(req.q("page") or 1)
        return 200, {"sha": sha, "parents": [{"sha": q} for q in c["parents"]],
                     "files": files[(page - 1) * per_page: page * per_page], "author": {"login": c["author"]},
                     "commit": {"verification": {"verified": c["verified"]}}}
