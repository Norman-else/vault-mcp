const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const templatePath = path.join(__dirname, '..', 'src', 'vault_mcp', 'templates', 'vault_ui.html');
const source = fs.readFileSync(templatePath, 'utf8');

function extractFunction(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `Could not find function ${name}`);

  const bodyStart = source.indexOf('{', start);
  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    const char = source[index];
    if (char === '{') {
      depth += 1;
    } else if (char === '}') {
      depth -= 1;
      if (depth === 0) {
        return source.slice(start, index + 1);
      }
    }
  }

  throw new Error(`Could not parse function ${name}`);
}

async function runCopyTest(field, value, shouldFail = false) {
  const clipboardWrites = [];
  const toastCalls = [];
  const context = {
    document: {
      getElementById(id) {
        assert.equal(id, `${field}-value`);
        return {
          getAttribute(name) {
            assert.equal(name, 'data-value');
            return value;
          },
        };
      },
    },
    navigator: {
      clipboard: {
        writeText(text) {
          clipboardWrites.push(text);
          return shouldFail ? Promise.reject(new Error('denied')) : Promise.resolve();
        },
      },
    },
    showToast(...args) {
      toastCalls.push(args);
    },
  };

  vm.createContext(context);
  vm.runInContext(extractFunction('copyCredentialField'), context);
  context.copyCredentialField(field);
  await new Promise((resolve) => setImmediate(resolve));

  return { clipboardWrites, toastCalls };
}

(async () => {
  const usernameResult = await runCopyTest('username', 'service-user');
  assert.deepEqual(usernameResult.clipboardWrites, ['service-user']);
  assert.deepEqual(usernameResult.toastCalls, [['Username copied to clipboard']]);

  const passwordResult = await runCopyTest('password', 'secret-value');
  assert.deepEqual(passwordResult.clipboardWrites, ['secret-value']);
  assert.deepEqual(passwordResult.toastCalls, [['Password copied to clipboard']]);

  const failureResult = await runCopyTest('password', 'secret-value', true);
  assert.deepEqual(failureResult.clipboardWrites, ['secret-value']);
  assert.deepEqual(failureResult.toastCalls, [['Failed to copy password', 'error']]);
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
