"""Apply the small Windows lifecycle extension to the pinned official source."""
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
target = root / 'cmd/sing-box/cmd_run.go'
text = target.read_text()
if 'nettWatch' not in text:
    marker = 'func run() error {'
    start = text.index(marker)
    before, run = text[:start], text[start:]
    needle = '\tdefer signal.Stop(osSignals)'
    assert run.count(needle) == 1
    run = run.replace(needle, needle + '\n\tstopWatch := nettWatch(osSignals)\n\tdefer stopWatch()\n\tdefer nettCleanup()', 1)
    needle = '\t\truntimeDebug.FreeOSMemory()'
    assert run.count(needle) == 1
    run = run.replace(needle, '\t\tif err = nettMarkReady(); err != nil {\n\t\t\tcancel()\n\t\t\t_ = instance.Close()\n\t\t\treturn err\n\t\t}\n' + needle, 1)
    target.write_text(before + run)
shutil.copyfile(Path(__file__).with_name('nett_lifecycle_windows.go'), root / 'cmd/sing-box/nett_lifecycle_windows.go')
for name in ['cmd_version.go', 'cmd.go']:
    path = root / 'cmd/sing-box' / name
    if path.exists():
        text = path.read_text()
        text = text.replace('"sing-box version ', '"nett split core version ')
        text = text.replace('"sing-box"', '"nett-split-core"')
        text = text.replace('Print current version of sing-box', 'Print current version of Nett split core')
        path.write_text(text)
