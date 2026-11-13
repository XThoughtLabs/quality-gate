# Setting up the GitHub Apps of a stand

`setup_apps.py` creates and installs the GitHub Apps that a stage-A stand needs, by GitHub's App
Manifest flow: one app per role, each installed on one repository only, each key kept in a local file
and never in GitHub. It comes from the WorkFlow API pilot's setup script (version 2), with every value
of the pilot moved into a configuration file.

## The three roles

Each role has a fixed set of repository permissions, which is also the most it may ask for. The
configuration cannot add or raise a permission: a key the example does not show is refused, and the
script checks the manifest, GitHub's answer and the installation against the role's set.

| Role | Repository permissions |
|---|---|
| executor | `contents: write`, `pull_requests: write`; `issues: write` only with `issues = true` |
| reviewer | `contents: read`, `pull_requests: write`, `statuses: write` |
| controller | `contents: write`, `checks: write`, `pull_requests: read`, `statuses: read`; `issues: read` only with `issues = true` |

Every app also has `metadata: read`, which GitHub adds to every app. The manifests have the webhook
off and subscribe to no events.

## What it does, for each role

1. Checks that the app's name is new. GitHub answers "not found" both for a name nobody uses and for
   another account's private app, so on "not found" the script asks you to look at your app settings and
   type the name again; on any other answer it stops. Nothing is created before this passes (this closes
   the pilot's limitation O-14, where a rerun could create a second app).
2. Serves the manifest from `127.0.0.1` and opens your browser, where you click Create.
3. Exchanges GitHub's one-time code at once and checks the new app: name, owner, permissions, events.
4. Writes the private key into a file, never on a command line:
   - the executor's key and its app file (for the launcher) into `key_folder`, readable only by the
     executor's Windows user; your own user loses access;
   - the reviewer's and the controller's keys into the files the configuration names, readable only by
     your own Windows user, so the executor's user cannot read them.
5. Opens the installation page, where you install the app on the one repository.
6. Checks, as the app, that it has exactly one installation, on exactly that repository, with exactly
   the role's permissions.

It discards the client secret and the webhook secret, never prints a key or a secret, and writes no
temporary copy of a key. A key file is created with its own permissions from its first moment (an explicit
security descriptor), never with its folder's inherited access; the folder of the reviewer's and the
controller's keys must give access only to the operator, SYSTEM and Administrators (so not to Users,
Authenticated Users, Everyone, INTERACTIVE, Local account or the executor's user). GitHub's
one-time manifest code is exchanged by the script itself over HTTPS, never passed on a command line.

## Running it

On the stand's Windows machine, in your own terminal (not in an AI session), signed in to `gh` as the
owner, with a Python that has `cryptography` (made from `../locks/review.lock`):

```
copy setup.example.toml <a folder outside every repository>\setup.toml
notepad <that folder>\setup.toml          # replace every <...>
python -I setup_apps.py --config <that folder>\setup.toml [--role all|executor|reviewer|controller]
```

Before any app is created it checks: Windows, an interactive terminal, `gh`'s account and admin right
on the repository, each name, each key path (outside `C:\Users` for the executor's folder, outside every
repository and OneDrive for all, never an existing file), and that the executor's Windows user is a
separate, enabled, standard local user. At the end it prints each app's name, app ID, installation ID,
permissions and key file: write them into the stand's records.

The apps are created under the account `gh` is signed in as, which must be the configured owner; an
organization owner is not supported by this version.

## Tests

Offline, with a fake GitHub and a fake of the script's one Windows seam (the `Windows` class): no
network, no key, no Windows call. From this folder:

```
python -m pytest tests -q -p no:cacheprovider
```

They run on Windows and on Linux alike.
