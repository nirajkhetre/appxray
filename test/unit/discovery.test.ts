import { mkdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { HintIndex } from '../../src/discovery/hints.js';
import { execProgram, parseDesktopEntry, planLinux } from '../../src/discovery/linux.js';
import {
  folderFromDisplayIcon,
  parsePowerShellJson,
  parseRegQuery,
} from '../../src/discovery/registry.js';
import { planWindows } from '../../src/discovery/windows.js';
import { silentLogger } from '../../src/util/log.js';
import { tempDir } from '../helpers.js';

describe('Windows registry parsing', () => {
  it('parses reg.exe output, including values with spaces and empty data', () => {
    const output = [
      'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\slack',
      '    DisplayName    REG_SZ    Slack',
      '    DisplayVersion    REG_SZ    4.41.105',
      '    InstallLocation    REG_SZ    C:\\Users\\Ana María\\AppData\\Local\\slack',
      '    NoModify    REG_DWORD    0x1',
      '    Comments    REG_SZ',
      '',
      'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\nameless',
      '    InstallLocation    REG_SZ    C:\\Nowhere',
      '',
    ].join('\r\n');
    expect(parseRegQuery(output)).toEqual([
      {
        displayName: 'Slack',
        displayVersion: '4.41.105',
        installLocation: 'C:\\Users\\Ana María\\AppData\\Local\\slack',
      },
    ]);
  });

  it('parses PowerShell JSON for one entry or many', () => {
    const one =
      '{"DisplayName":"Discord","DisplayVersion":"1.0.9","Publisher":"Discord Inc.","InstallLocation":null,"DisplayIcon":"C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Discord\\\\app.ico"}';
    expect(parsePowerShellJson(one)).toEqual([
      {
        displayName: 'Discord',
        displayVersion: '1.0.9',
        publisher: 'Discord Inc.',
        displayIcon: 'C:\\Users\\u\\AppData\\Local\\Discord\\app.ico',
      },
    ]);
    expect(parsePowerShellJson(`[${one},{"DisplayName":"  "}]`)).toHaveLength(1);
    expect(parsePowerShellJson('')).toEqual([]);
  });

  it.each([
    ['"C:\\Program Files\\App\\app.exe",0', 'C:\\Program Files\\App'],
    ['C:\\Apps\\Tool\\tool.exe', 'C:\\Apps\\Tool'],
    ['C:\\Apps\\Tool\\icon.ico,-101', 'C:\\Apps\\Tool'],
    ['%SystemRoot%\\system32\\shell32.dll,4', undefined],
    ['msiexec.exe', undefined],
  ])('derives the install folder from DisplayIcon %s', (icon, expected) => {
    expect(folderFromDisplayIcon(icon)).toBe(expected);
  });
});

describe('planWindows', () => {
  const env = {
    ProgramFiles: 'C:\\Program Files',
    'ProgramFiles(x86)': 'C:\\Program Files (x86)',
    LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local',
    APPDATA: 'C:\\Users\\u\\AppData\\Roaming',
    ProgramData: 'C:\\ProgramData',
  };

  it('searches the standard install roots and adds registry locations outside them', async () => {
    const plan = await planWindows({
      env,
      allUsers: false,
      logger: silentLogger,
      uninstallEntries: [
        { displayName: 'Custom Tool', displayVersion: '2.0', installLocation: 'D:\\Tools\\Custom' },
        {
          displayName: 'Slack',
          displayVersion: '4.41.105',
          displayIcon: 'C:\\Users\\u\\AppData\\Local\\slack\\app.ico',
        },
        { displayName: 'Broken', installLocation: 'C:\\Program Files' },
      ],
    });
    const roots = plan.roots.map((root) => root.path);
    expect(roots).toEqual(
      expect.arrayContaining([
        'C:\\Program Files',
        'C:\\Program Files (x86)',
        'C:\\Users\\u\\AppData\\Local\\Programs',
        'C:\\Users\\u\\AppData\\Local',
        'D:\\Tools\\Custom',
      ]),
    );
    expect(roots).not.toContain('C:\\Users\\u\\AppData\\Local\\slack');
    expect(plan.hints.lookup('C:\\Users\\u\\AppData\\Local\\slack\\app-4.41.105')).toEqual({
      name: 'Slack',
      version: '4.41.105',
    });
    // An install location that is a whole root must not name every app under it.
    expect(plan.hints.lookup('C:\\Program Files\\Other')).toBeUndefined();
  });
});

describe('HintIndex', () => {
  it('prefers the deepest matching folder and ignores case on Windows', () => {
    const index = new HintIndex('win32');
    index.add('C:\\Apps', { name: 'Suite' });
    index.add('C:\\Apps\\Editor', { name: 'Editor' });
    expect(index.lookup('c:\\apps\\editor\\bin')).toEqual({ name: 'Editor' });
    expect(index.lookup('C:\\Apps\\Other')).toEqual({ name: 'Suite' });
    expect(index.lookup('C:\\Elsewhere')).toBeUndefined();
  });
});

describe('Linux discovery plan', () => {
  let dir: string;
  let cleanup: () => Promise<void>;
  beforeEach(async () => ({ dir, cleanup } = await tempDir()));
  afterEach(async () => cleanup());

  it.skipIf(process.platform === 'win32')(
    'adds snaps, flatpaks and names from .desktop files, and lists AppImages',
    async () => {
      const at = (p: string) => path.join(dir, p);
      await mkdir(at('snap/signal-desktop/current'), { recursive: true });
      await mkdir(at('snap/core22/current'), { recursive: true });
      await mkdir(at('var/lib/flatpak/app/com.slack.Slack/current/active/files'), {
        recursive: true,
      });
      await mkdir(at('usr/share/code/bin'), { recursive: true });
      await writeFile(at('usr/share/code/bin/code'), '#!/bin/sh');
      await mkdir(at('usr/bin'), { recursive: true });
      await symlink(at('usr/share/code/bin/code'), at('usr/bin/code'));
      await mkdir(at('usr/share/applications'), { recursive: true });
      await writeFile(
        at('usr/share/applications/code.desktop'),
        '[Desktop Entry]\nName=Visual Studio Code\nExec=code --unity-launch %F\n[Desktop Action new]\nName=New Window\n',
      );
      await mkdir(at('home/u/Applications'), { recursive: true });
      await writeFile(at('home/u/Applications/Tool.AppImage'), '');

      const plan = await planLinux({
        env: { PATH: '/usr/bin' },
        home: '/home/u',
        allUsers: false,
        prefix: dir,
      });
      const roots = plan.roots.map((root) => path.relative(dir, root.path));
      expect(roots).toContain('snap/signal-desktop/current');
      expect(roots).not.toContain('snap/core22/current');
      expect(roots).toContain('var/lib/flatpak/app/com.slack.Slack/current/active/files');
      expect(plan.hints.lookup(at('usr/share/code'))).toEqual({ name: 'Visual Studio Code' });
      expect(plan.skipped.map((item) => path.basename(item.path))).toEqual(['Tool.AppImage']);
    },
  );

  it('parses only the main .desktop group', () => {
    expect(
      parseDesktopEntry(
        '[Desktop Action x]\nName=Other\n[Desktop Entry]\nName=App\nExec="/opt/My App/app" %U\n',
      ),
    ).toEqual({ name: 'App', exec: '"/opt/My App/app" %U' });
    expect(parseDesktopEntry('[Desktop Entry]\nName=No exec\n')).toBeNull();
  });

  it.each([
    ['/usr/share/code/code --unity-launch %F', '/usr/share/code/code'],
    ['"/opt/My App/app" %U', '/opt/My App/app'],
    ['env BAMF_DESKTOP_FILE_HINT=x LANG=C /snap/bin/signal %U', '/snap/bin/signal'],
    ['', undefined],
  ])('extracts the program from Exec=%s', (exec, expected) => {
    expect(execProgram(exec)).toBe(expected);
  });
});
