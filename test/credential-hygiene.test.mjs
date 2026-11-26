import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const setup = readFileSync(path.join(root, 'setup.sh'), 'utf8');
const readme = readFileSync(path.join(root, 'README.md'), 'utf8');

function extractHeredoc(source, marker) {
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing ${marker}`);
  const afterMarker = source.indexOf('\n', start);
  const rest = source.slice(afterMarker + 1);
  const end = rest.indexOf('\nEOF\n');
  assert.notEqual(end, -1, `unterminated ${marker}`);
  return rest.slice(0, end);
}

function recordedQuery() {
  const calls = [];
  return {
    calls,
    queryInterface: {
      async bulkInsert(table, rows) {
        calls.push({ table, rows });
      },
    },
  };
}

async function loadSeeder() {
  const dir = await mkdtemp(path.join(tmpdir(), 'appstarter-seed-'));
  const seederPath = path.join(dir, 'db', 'seeders', '20231010121000-seed-rbac.js');
  const bcryptDir = path.join(dir, 'node_modules', 'bcrypt');
  await mkdir(path.dirname(seederPath), { recursive: true });
  await mkdir(bcryptDir, { recursive: true });
  await writeFile(
    path.join(bcryptDir, 'package.json'),
    JSON.stringify({ name: 'bcrypt', main: 'index.js' }),
  );
  await writeFile(
    path.join(bcryptDir, 'index.js'),
    [
      'module.exports.hash = async function hash(value, rounds) {',
      "  if (typeof value !== 'string' || value.trim() === '') throw new Error('empty hash input');",
      "  return 'hashed:' + value.length + ':' + rounds;",
      '};',
      '',
    ].join('\n'),
  );
  await writeFile(
    seederPath,
    extractHeredoc(setup, "cat > db/seeders/20231010121000-seed-rbac.js << 'EOF'"),
  );
  const seeder = createRequire(seederPath)(seederPath);
  return {
    seeder,
    async cleanup() {
      await rm(dir, { recursive: true, force: true });
    },
  };
}

async function withAdminEnv(email, password, run) {
  const previous = {
    email: process.env.ADMIN_EMAIL,
    password: process.env.ADMIN_PASSWORD,
  };
  if (email === undefined) delete process.env.ADMIN_EMAIL;
  else process.env.ADMIN_EMAIL = email;
  if (password === undefined) delete process.env.ADMIN_PASSWORD;
  else process.env.ADMIN_PASSWORD = password;
  try {
    return await run();
  } finally {
    if (previous.email === undefined) delete process.env.ADMIN_EMAIL;
    else process.env.ADMIN_EMAIL = previous.email;
    if (previous.password === undefined) delete process.env.ADMIN_PASSWORD;
    else process.env.ADMIN_PASSWORD = previous.password;
  }
}

function randomEmail() {
  return `user-${randomBytes(8).toString('hex')}@invalid.test`;
}

function randomSecret() {
  return randomBytes(18).toString('base64url');
}

test('setup.sh passes bash -n', () => {
  execFileSync('bash', ['-n', path.join(root, 'setup.sh')], { stdio: 'pipe' });
});

test('login fields start empty and no useState string is prefilled', () => {
  const login = extractHeredoc(setup, "cat > src/pages/Login.tsx << 'EOF'");
  assert.match(login, /const \[email, setEmail\] = useState\(''\);/);
  assert.match(login, /const \[password, setPassword\] = useState\(''\);/);
  const values = [...setup.matchAll(/useState\('([^']*)'\)/g)].map((match) => match[1]);
  assert.ok(values.length >= 2);
  for (const value of values) {
    assert.equal(value, '');
  }
});

test('seeder has no credential fallback and .env.example names empty vars', () => {
  const seeder = extractHeredoc(setup, "cat > db/seeders/20231010121000-seed-rbac.js << 'EOF'");
  const example = extractHeredoc(setup, "cat > .env.example << 'EOF'");
  assert.match(seeder, /process\.env\.ADMIN_EMAIL/);
  assert.match(seeder, /process\.env\.ADMIN_PASSWORD/);
  assert.equal(seeder.includes('ADMIN_EMAIL ||'), false);
  assert.equal(seeder.includes('ADMIN_PASSWORD ||'), false);
  assert.equal(seeder.includes('ADMIN_EMAIL ??'), false);
  assert.equal(seeder.includes('ADMIN_PASSWORD ??'), false);
  assert.match(example, /^ADMIN_EMAIL=$/m);
  assert.match(example, /^ADMIN_PASSWORD=$/m);
  for (const line of example.split('\n')) {
    if (line.startsWith('ADMIN_EMAIL=') || line.startsWith('ADMIN_PASSWORD=')) {
      assert.equal(line.slice(line.indexOf('=') + 1), '');
    }
  }
  assert.match(readme, /ADMIN_EMAIL/);
  assert.match(readme, /ADMIN_PASSWORD/);
  assert.equal(readme.includes('ADMIN_EMAIL='), false);
  assert.equal(readme.includes('ADMIN_PASSWORD='), false);
});

test('seeder refuses to write when either admin variable is missing', async () => {
  const { seeder, cleanup } = await loadSeeder();
  const email = randomEmail();
  const secret = randomSecret();
  try {
    const cases = [
      {
        email: undefined,
        password: undefined,
        message: 'Refusing to seed. Set ADMIN_EMAIL and ADMIN_PASSWORD in the environment. No default admin account is provided.',
      },
      {
        email,
        password: undefined,
        message: 'Refusing to seed. Set ADMIN_PASSWORD in the environment. No default admin account is provided.',
      },
      {
        email: undefined,
        password: secret,
        message: 'Refusing to seed. Set ADMIN_EMAIL in the environment. No default admin account is provided.',
      },
      {
        email: '   ',
        password: '   ',
        message: 'Refusing to seed. Set ADMIN_EMAIL and ADMIN_PASSWORD in the environment. No default admin account is provided.',
      },
    ];
    for (const item of cases) {
      const recorded = recordedQuery();
      await withAdminEnv(item.email, item.password, async () => {
        await assert.rejects(
          () => seeder.up(recorded.queryInterface, {}),
          { message: item.message },
        );
      });
      assert.equal(recorded.calls.length, 0);
    }
  } finally {
    await cleanup();
  }
});

test('seeder stores only the supplied email and a hash when both variables are set', async () => {
  const { seeder, cleanup } = await loadSeeder();
  const email = `  ${randomEmail()}  `;
  const secret = randomSecret();
  const recorded = recordedQuery();
  try {
    await withAdminEnv(email, secret, async () => {
      await seeder.up(recorded.queryInterface, {});
    });
    const users = recorded.calls.find((call) => call.table === 'Users');
    assert.ok(users);
    assert.equal(users.rows.length, 1);
    assert.equal(users.rows[0].email, email.trim());
    assert.equal(users.rows[0].passwordHash, `hashed:${secret.length}:12`);
    assert.notEqual(users.rows[0].passwordHash, secret);
    const serialized = JSON.stringify(recorded.calls);
    assert.equal(serialized.includes(secret), false);
    assert.deepEqual(
      recorded.calls.map((call) => call.table),
      ['Roles', 'Permissions', 'RolePermissions', 'Users', 'UserRoles'],
    );
  } finally {
    await cleanup();
  }
});
