# The launcher's git hooks folder

`xtl_launcher.py` points every git command it runs at this folder with `core.hooksPath` (LAUNCHER-CONTRACT.md, LR-80), so that no hook runs: not one the model wrote into its clone, and not one in any folder the model's Windows user can write. This file is the only one the folder may hold, and the executor's Windows user must not be able to create a file here. The launcher's preflight checks both and stops with `SELF_WRITABLE` otherwise (LR-10).
