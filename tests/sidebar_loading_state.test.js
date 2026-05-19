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

class FakeClassList {
  constructor(classes = []) {
    this.classes = new Set(classes);
  }

  add(name) {
    this.classes.add(name);
  }

  remove(name) {
    this.classes.delete(name);
  }

  contains(name) {
    return this.classes.has(name);
  }
}

class FakeElement {
  constructor(classes) {
    this.classList = new FakeClassList(classes);
  }
}

function matchesSelector(element, selector) {
  const requiredClasses = selector
    .trim()
    .split('.')
    .filter(Boolean);
  return requiredClasses.every((name) => element.classList.contains(name));
}

function createDocument(elements) {
  return {
    querySelectorAll(selector) {
      const selectors = selector.split(',');
      return elements.filter((element) => selectors.some((part) => matchesSelector(element, part)));
    },
  };
}

function loadSidebarStateFunctions(document) {
  const context = { document };
  vm.createContext(context);
  vm.runInContext(
    [
      extractFunction('clearSidebarLoadingState'),
      extractFunction('clearSidebarActiveState'),
      extractFunction('setSidebarLoadingState'),
    ].join('\n'),
    context,
  );
  return context;
}

{
  const previousSecret = new FakeElement(['tree-item', 'active']);
  const nextSecret = new FakeElement(['tree-item']);
  const selectedDbRole = new FakeElement(['db-role-item', 'active']);
  const staleLoadingItem = new FakeElement(['tree-item', 'loading']);
  const { setSidebarLoadingState } = loadSidebarStateFunctions(
    createDocument([previousSecret, nextSecret, selectedDbRole, staleLoadingItem]),
  );

  setSidebarLoadingState(nextSecret);

  assert.equal(previousSecret.classList.contains('active'), false);
  assert.equal(nextSecret.classList.contains('loading'), true);
  assert.equal(staleLoadingItem.classList.contains('loading'), false);
  assert.equal(selectedDbRole.classList.contains('active'), true);
}

{
  const selectedSecret = new FakeElement(['tree-item', 'active']);
  const previousDbRole = new FakeElement(['db-role-item', 'active']);
  const nextDbRole = new FakeElement(['db-role-item']);
  const { setSidebarLoadingState } = loadSidebarStateFunctions(
    createDocument([selectedSecret, previousDbRole, nextDbRole]),
  );

  setSidebarLoadingState(nextDbRole);

  assert.equal(previousDbRole.classList.contains('active'), false);
  assert.equal(nextDbRole.classList.contains('loading'), true);
  assert.equal(selectedSecret.classList.contains('active'), true);
}
