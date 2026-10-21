import pathlib
import shutil
import subprocess as sp
import tempfile
import unittest


class DeploySyncTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which('rsync'), 'rsync is required')
    def test_runtime_sync_adds_updates_deletes_and_excludes_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source, target = root / 'source', root / 'target'
            source.mkdir()
            target.mkdir()
            for path in (
                'main.py',
                'new_module.py',
                '.python-version',
                'templates/page.html',
                'static/health.js',
                'ansible/scripts/generate_passwd.py',
                'data/reputation.json',
                '.env',
                '.git/config',
                'build/binary',
                'logs/access.log',
                'state/bans.json',
                '__pycache__/main.pyc',
            ):
                file = source / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('new')
            for path in (
                'main.py',
                'deleted.py',
                'static/removed.js',
                'dist/px-manager',
                '.venv/old',
                'ansible-scripts/old.py',
            ):
                file = target / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('old')
            result = sp.run(
                [
                    'rsync',
                    '-ac',
                    '--delay-updates',
                    '--no-owner',
                    '--no-group',
                    '--chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r',
                    '--delete',
                    '--delete-excluded',
                    '--filter=merge '
                    + str(
                        pathlib.Path(__file__).resolve().parents[1]
                        / 'ansible/rsync-filter'
                    ),
                    str(source) + '/',
                    str(target) + '/',
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                {
                    'main.py',
                    'new_module.py',
                    '.python-version',
                    'templates/page.html',
                    'static/health.js',
                    'ansible/scripts/generate_passwd.py',
                },
                {
                    str(path.relative_to(target))
                    for path in target.rglob('*')
                    if path.is_file()
                },
            )
            self.assertEqual('new', (target / 'main.py').read_text())
