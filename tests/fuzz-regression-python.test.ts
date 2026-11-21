import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { ProtectionIntensity } from "../src/core/types.js";
import { protectTarget } from "../src/engine/protector.js";
import {
  InvalidPythonSourceError,
  findPythonPrologueInsertionOffset,
  protectPythonPycBuffer,
  protectPythonSource,
} from "../src/shields/formats/python.js";
import { layoutForPycMagic } from "../src/shields/formats/python-pyc-weave.js";
import { PY3, python3 } from "./helpers/python-interpreter.js";

/**
 * Regression tests for the Python shields (fuzz findings 07, 09, 10, 12, 13,
 * 15, 17, 18 and 20).
 *
 * Every finding was "the hardened file no longer behaves like the original",
 * so nearly every test here runs the original and the hardened program under
 * the local CPython and compares what they do. Checks that inspect code do it
 * with CPython's own `ast` / `marshal` / `tokenize`, not with string matching.
 */

const py = String.raw;

const scratch = mkdtempSync(join(tmpdir(), "bla-fuzz-python-"));
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

let dirCounter = 0;
function scratchDir(label: string): string {
  dirCounter += 1;
  const dir = join(scratch, `${dirCounter}-${label}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** `[major, minor]` of the interpreter the tests run programs with. */
const PY_VERSION: readonly [number, number] = PY3
  ? (JSON.parse(
      execFileSync(PY3, ["-c", "import json, sys; print(json.dumps(list(sys.version_info[:2])))"], {
        encoding: "utf8",
        stdio: "pipe",
      }),
    ) as [number, number])
  : [0, 0];

function pythonAtLeast(major: number, minor: number): boolean {
  return PY_VERSION[0] > major || (PY_VERSION[0] === major && PY_VERSION[1] >= minor);
}

/** Runs a helper script in isolated mode and parses the JSON it prints. */
function runPythonJson<T>(script: string, args: readonly string[]): T {
  const scriptPath = join(scratchDir("driver"), "driver.py");
  writeFileSync(scriptPath, script, "utf8");
  let stdout: string;
  try {
    stdout = execFileSync(python3(), ["-I", "-B", scriptPath, ...args], {
      encoding: "utf8",
      stdio: "pipe",
      timeout: 240_000,
      maxBuffer: 256 * 1024 * 1024,
    });
  } catch (err) {
    // Surface the helper's own traceback rather than just "Command failed".
    const failure = err as { stderr?: unknown; status?: unknown; signal?: unknown; message?: string };
    throw new Error(
      `Python helper failed (status ${String(failure.status)}, signal ${String(failure.signal)}): ` +
        `${typeof failure.stderr === "string" && failure.stderr ? failure.stderr : failure.message}`,
    );
  }
  return JSON.parse(stdout) as T;
}

// ---------------------------------------------------------------------------
// Scenario runner: original vs hardened module, driven by the same main.py
// ---------------------------------------------------------------------------

interface ShieldConfig {
  readonly label: string;
  readonly intensity: ProtectionIntensity;
  readonly weaveDecoys: boolean;
}

/** Stealth weaves the shared-state touch only; the others add the guarded decoy call. */
const CONFIGS: readonly ShieldConfig[] = [
  { label: "stealth+weave", intensity: "stealth", weaveDecoys: true },
  { label: "balanced", intensity: "balanced", weaveDecoys: false },
  { label: "balanced+weave", intensity: "balanced", weaveDecoys: true },
  { label: "maximum+weave", intensity: "maximum", weaveDecoys: true },
  { label: "bankrupt+weave", intensity: "bankrupt", weaveDecoys: true },
];

interface Scenario {
  readonly name: string;
  /** `mod.py`. Text is passed to the shield as a string, bytes as bytes. */
  readonly module: string | Buffer;
  /** `main.py`; defaults to {@link DEFAULT_MAIN}. */
  readonly main?: string;
}

interface RunResult {
  readonly stdout: string;
  /** `ExceptionType: message`, or null when the program ran to completion. */
  readonly error: string | null;
  /** Source encoding CPython detects for `mod.py`. */
  readonly encoding: string;
}

interface ScenarioOutcome {
  readonly scenario: Scenario;
  readonly original: RunResult;
  readonly hardened: ReadonlyMap<string, RunResult>;
}

/**
 * Imports the module, uses it, then reloads it twice. `importlib.reload()`
 * re-executes the module body in the namespace the first import left behind,
 * which is where injected code that leans on the module's names falls over.
 */
const DEFAULT_MAIN = py`import importlib
import mod


def show(stage):
    print(stage, repr(mod.__doc__), mod.run())


show("import")
importlib.reload(mod)
show("reload")
importlib.reload(mod)
show("reload again")
`;

/**
 * Runs each job's main.py in-process with stdout captured. What a job can leave
 * behind for the next one is undone afterwards: names it added to `builtins`
 * (gettext's `_`), its `sys.path` entry and the `mod` module itself. Other
 * modules stay loaded — dropping a C extension such as `unicodedata` from
 * `sys.modules` leaves CPython 3.11–3.13 with a dangling pointer.
 */
const SCENARIO_DRIVER = py`import builtins, contextlib, importlib, io, json, os, runpy, sys, tokenize

sys.dont_write_bytecode = True
with open(sys.argv[1], encoding="utf-8") as handle:
    jobs = json.load(handle)

results = []
for job in jobs:
    builtin_namespace = vars(builtins)
    saved_builtins = dict(builtin_namespace)
    saved_path = list(sys.path)
    captured = io.StringIO()
    error = None
    try:
        sys.path.insert(0, job)
        importlib.invalidate_caches()
        with contextlib.redirect_stdout(captured):
            runpy.run_path(os.path.join(job, "main.py"), run_name="__main__")
    except BaseException as exc:
        error = "%s: %s" % (type(exc).__name__, exc)
    finally:
        for name in list(builtin_namespace):
            if name not in saved_builtins:
                del builtin_namespace[name]
        for name, value in saved_builtins.items():
            if builtin_namespace.get(name, builtin_namespace) is not value:
                builtin_namespace[name] = value
        sys.modules.pop("mod", None)
        sys.path[:] = saved_path
    try:
        with open(os.path.join(job, "mod.py"), "rb") as handle:
            encoding = tokenize.detect_encoding(handle.readline)[0]
    except SyntaxError as exc:
        encoding = "undetectable: %s" % exc
    results.append({"stdout": captured.getvalue(), "error": error, "encoding": encoding})

json.dump(results, sys.stdout)
`;

function hardenScenarioModule(scenario: Scenario, config: ShieldConfig): string {
  return protectPythonSource(scenario.module, {
    intensity: config.intensity,
    weaveDecoys: config.weaveDecoys,
    seed: `fuzz-regression:${scenario.name}`,
  }).code;
}

function runScenarios(scenarios: readonly Scenario[]): ScenarioOutcome[] {
  const jobs: string[] = [];
  const addJob = (scenario: Scenario, variant: string, moduleBytes: string | Buffer): void => {
    const dir = scratchDir(`${scenario.name}-${variant}`.replace(/[^A-Za-z0-9+_-]/g, "_"));
    writeFileSync(join(dir, "mod.py"), moduleBytes);
    writeFileSync(join(dir, "main.py"), scenario.main ?? DEFAULT_MAIN, "utf8");
    jobs.push(dir);
  };
  for (const scenario of scenarios) {
    addJob(scenario, "original", scenario.module);
    for (const config of CONFIGS) {
      // Hardened output is UTF-8 text: written the way the engine writes it.
      addJob(scenario, config.label, hardenScenarioModule(scenario, config));
    }
  }

  const manifest = join(scratchDir("manifest"), "jobs.json");
  writeFileSync(manifest, JSON.stringify(jobs), "utf8");
  const results = runPythonJson<RunResult[]>(SCENARIO_DRIVER, [manifest]);

  let cursor = 0;
  return scenarios.map((scenario) => {
    const original = results[cursor++]!;
    const hardened = new Map<string, RunResult>();
    for (const config of CONFIGS) hardened.set(config.label, results[cursor++]!);
    return { scenario, original, hardened };
  });
}

const behaviour = (result: RunResult) => ({ stdout: result.stdout, error: result.error });

/** The hardened module must do exactly what the original does, at every intensity. */
function expectSameBehaviour(scenarios: readonly Scenario[]): ScenarioOutcome[] {
  const outcomes = runScenarios(scenarios);
  for (const { scenario, original, hardened } of outcomes) {
    // A scenario that fails on its own says nothing about the shield.
    expect(original.error, `${scenario.name}: the original must run on this interpreter`).toBeNull();
    for (const [label, result] of hardened) {
      expect(behaviour(result), `${scenario.name} [${label}]`).toEqual(behaviour(original));
    }
  }
  return outcomes;
}

// ---------------------------------------------------------------------------
// Findings 07, 09, 10, 17: names the injected code binds or resolves
// ---------------------------------------------------------------------------

const GETTEXT_UNDERSCORE: Scenario = {
  name: "gettext-builtin-underscore",
  module: py`"""Greeter that relies on gettext's builtin _()."""
TITLE = _("Title")


def greet(name):
    return _("Hello, %s") % name
`,
  main: py`import gettext
import importlib

gettext.install("bla_fuzz_regression_domain")  # binds builtins._

import mod

print(mod.TITLE, mod.greet("ann"))
importlib.reload(mod)
print(mod.TITLE, mod.greet("bob"))
print("module binds _:", "_" in vars(mod))
`,
};

const UNDERSCORE_IN_FUNCTIONS: Scenario = {
  name: "underscore-inside-functions",
  module: py`"""Functions that use _ the way real code does."""


def _(text):
    return "<" + text + ">"


def uses_module_underscore(count):
    return _("item") + str(count)


def declares_global():
    global _
    return _("global")


def closure():
    _ = lambda text: "inner:" + text

    def inner():
        return _("closure")

    return inner()


def discards():
    total = 0
    for _ in (1, 2, 3):
        total += 1
    first, _, last = ("a", "b", "c")
    return [total, first + last]


def run():
    return [uses_module_underscore(2), declares_global(), closure(), discards()]
`,
};

const BUILTIN_NAMES_AS_LOCALS: Scenario = {
  name: "builtin-names-as-parameters-and-locals",
  module: py`"""Parameters and locals named like builtins."""


def digest(data, hash=None):
    return [data, hash]


def local_hash():
    hash = 5
    return hash + 1


def shadows(len, int, id, type, sum, ord, range, max, min, abs, bytearray, enumerate, isinstance):
    return [len, int, id, type, sum, ord, range, max, min, abs, bytearray, enumerate, isinstance]


def late_binding():
    values = [1, 2]
    len = 3
    return len + values[0]


class Box:
    def hash(self):
        return "box"

    def describe(self, hash="h"):
        return self.hash() + hash


def run():
    return [
        digest("d"),
        digest("d", hash=1),
        local_hash(),
        shadows(*"abcdefghijklm"),
        late_binding(),
        Box().describe(),
    ]
`,
};

const MODULE_REBINDS_HASH: Scenario = {
  name: "module-imports-its-own-hash",
  module: py`"""Module that imports its own hash."""
from hashlib import sha256 as hash


def fingerprint(data):
    return hash(data).hexdigest()[:16]


def run():
    return fingerprint(b"payload")
`,
};

const MODULE_SHADOWS_BUILTINS: Scenario = {
  name: "module-level-names-shadow-builtins",
  module: py`"""Module-level names that shadow builtins."""


def len(obj):
    raise RuntimeError("the module's own len() was called")


def hash(obj):
    raise RuntimeError("the module's own hash() was called")


class Exception(BaseException):
    pass


range = ord = bytearray = enumerate = max = min = sum = abs = None
int = float = str = bytes = dict = list = tuple = set = None
isinstance = getattr = print = None


def run():
    return 7
`,
};

/** Customer code that uses no builtin at all, so every builtin use in the result is injected. */
const ARITHMETIC_MODULE = py`"""Arithmetic only: uses no builtin at all."""


def add(left, right):
    return left + right


def scale(value):
    return value * 2
`;

const POISONED_BUILTINS: Scenario = {
  name: "every-builtin-name-rebound",
  module: ARITHMETIC_MODULE,
  // Executes the module body in a namespace where every builtin name is already
  // bound to an object that raises when used: the state importlib.reload()
  // leaves a module in when it defines those names itself. Then calls every
  // function the namespace holds, injected ones included.
  main: py`import builtins, inspect, os, types


class Poison:
    def __init__(self, name):
        self.__dict__["name"] = name

    def _used(self, *args, **kwargs):
        raise RuntimeError("injected code used the module's own binding of %r" % self.__dict__["name"])

    __call__ = __getitem__ = __iter__ = __len__ = __bool__ = __contains__ = _used

    def __getattr__(self, attribute):
        self._used()


source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mod.py")
with open(source_path, "rb") as handle:
    code = compile(handle.read(), source_path, "exec")

namespace = {"__name__": "mod", "__file__": source_path}
namespace.update((name, Poison(name)) for name in dir(builtins) if not name.startswith("__"))
exec(code, namespace)

injected = 0
for name, value in sorted(namespace.items()):
    if not isinstance(value, types.FunctionType) or value.__globals__ is not namespace:
        continue
    if name in ("add", "scale") or name.startswith("__"):
        continue  # the module's own functions; __annotate__ (3.14) belongs to the compiler
    value()
    value(*[3, 2][: len(inspect.signature(value).parameters)])
    injected += 1

print(namespace["add"](2, 3), namespace["scale"](4))
print("injected functions exercised:", injected > 0)
`,
};

const STATIC_NAME_AUDIT: Scenario = {
  name: "static-audit-of-injected-names",
  module: ARITHMETIC_MODULE,
  // CPython's own parser: which builtin names the module's code mentions outside
  // annotations, and which module-level names it binds that are not generated
  // (no 4-hex-digit group). For the original that is [] and ['add', 'scale'].
  main: py`import ast, builtins, os, re

source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mod.py")
with open(source_path, "rb") as handle:
    tree = ast.parse(handle.read(), source_path)

annotation_nodes = set()
for node in ast.walk(tree):
    spots = []
    if isinstance(node, ast.arg):
        spots.append(node.annotation)
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        spots.append(node.returns)
    elif isinstance(node, ast.AnnAssign):
        spots.append(node.annotation)
    for spot in spots:
        if spot is not None:
            annotation_nodes.update(id(sub) for sub in ast.walk(spot))

builtin_names = set(dir(builtins))
print(sorted({
    node.id
    for node in ast.walk(tree)
    if isinstance(node, ast.Name) and node.id in builtin_names and id(node) not in annotation_nodes
}))

bound = set()
for statement in tree.body:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        bound.add(statement.name)
    elif isinstance(statement, (ast.Import, ast.ImportFrom)):
        bound.update((alias.asname or alias.name).split(".")[0] for alias in statement.names)
    else:
        bound.update(
            node.id for node in ast.walk(statement)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        )
print(sorted(
    name for name in bound
    if not (
        re.search(r"(?:^|_)[0-9a-fA-F]{4}(?:_|$)", name)
        or (name.count("_") >= 2 and re.search(r"(?:^|_)[g-zG-Z][0-9a-zA-Z]{3}(?:_|$)", name))
    )
))
`,
};

// ---------------------------------------------------------------------------
// Findings 13 and 18: where the injected code is inserted
// ---------------------------------------------------------------------------

const PROLOGUE_SCENARIOS: readonly Scenario[] = [
  {
    name: "docstring-then-semicolon-import",
    module: py`"""Module doc."""; import sys


def run():
    return sys.maxsize > 0
`,
  },
  {
    name: "docstring-then-semicolon-assignments",
    module: py`'''Doc''' ; X = 1 ; Y = X + 1


def run():
    return [X, Y]
`,
  },
  {
    name: "docstring-and-future-import-on-one-line",
    module: py`"""Doc."""; from __future__ import annotations
import sys


def run(value: NotDefinedAnywhere = 1):
    return [value, run.__annotations__["value"]]
`,
  },
  {
    name: "future-import-then-semicolon-import",
    module: py`from __future__ import annotations; import os


def run(value: NotDefinedAnywhere = 2) -> NotDefinedAnywhere:
    return [value, len(os.sep), sorted(run.__annotations__.values())]
`,
  },
  {
    name: "docstring-continued-onto-semicolon-line",
    module: py`"""Doc""" \
; X = 5


def run():
    return X
`,
  },
  {
    name: "shebang-cookie-docstring-parenthesised-future-imports",
    module: py`#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Doc with shebang and cookie."""
# comment between
from __future__ import (
    annotations,   # trailing comment
    division,
)
from __future__ import generator_stop as _gs, print_function


def run(a: NotDefinedAnywhere = 1):
    return [a, 3 / 2, _gs.compiler_flag > 0]
`,
  },
  {
    name: "crlf-docstring-with-trailing-comment",
    module: '"""Doc."""  # comment\r\nimport sys\r\n\r\n\r\ndef run():\r\n    return sys.byteorder in ("little", "big")\r\n',
  },
  {
    name: "implicitly-concatenated-module-docstring",
    module: py`"module " "docstring " \
    "in three parts"
VALUE = 3


def run():
    return VALUE
`,
  },
  {
    name: "parenthesised-module-docstring",
    module: py`(
    "parenthesised "
    "module docstring"
)
import sys


def run():
    return sys.byteorder in ("little", "big")
`,
  },
  {
    name: "first-statement-is-a-multi-line-expression",
    module: py`VALUES = [
    1,
    2,
]


def run():
    return VALUES
`,
  },
  {
    name: "first-statement-is-bytes-not-a-docstring",
    module: py`b"not a docstring"


def run():
    return 1
`,
  },
  {
    name: "docstring-semicolon-no-trailing-newline",
    module: '"""Doc"""; X = 1\ndef run():\n    return X',
  },
];

const FUNCTION_DOCSTRINGS: Scenario = {
  name: "function-docstring-forms",
  module: py`"""Function docstring forms."""


def semicolon_after_doc():
    """Doc of f."""; x = 1
    return x


def one_line_doc_then_return():
    'one-line'; return 2


def multi_line_doc_then_statements():
    """multi
    line"""; y = 3; z = y + 1
    return z


def concatenated():
    "part one, " "part two"
    return 1


def concatenated_in_parens():
    ("first line "
     "second line")
    return 2


def continued():
    "alpha " \
    "beta"
    return 3


def raw_doc():
    r"""raw \d doc"""
    return 4


def legacy_prefix():
    u'legacy'
    return 5


def mixed_quotes():
    """triple """ 'single ' "double"
    return 6


def bytes_first():
    b"bytes are not a docstring"
    return 7


def fstring_first():
    f"neither is an f-string {1}"
    return 8


def expression_first():
    "a" + "b"
    return 9


def nested_parens():
    (("nested parens"))
    return 10


def doc_then_comments():
    "doc"  # trailing comment
    # another comment
    return 11


async def coroutine():
    "async " "doc"
    return 12


class Shape:
    "class doc " "concatenated"

    def area(self):
        '''method ''' """doc"""
        return 13

    @staticmethod
    def unit(): return 14


def one_liner(): return 15


def run():
    functions = [
        semicolon_after_doc, one_line_doc_then_return, multi_line_doc_then_statements,
        concatenated, concatenated_in_parens, continued, raw_doc, legacy_prefix, mixed_quotes,
        bytes_first, fstring_first, expression_first, nested_parens, doc_then_comments,
    ]
    rows = [[f.__name__, f.__doc__, f()] for f in functions]
    rows.append(["coroutine", coroutine.__doc__])
    rows.append(["Shape", Shape.__doc__, Shape.area.__doc__, Shape().area(), Shape.unit(), one_liner()])
    return rows
`,
};

// ---------------------------------------------------------------------------
// Finding 20: f-strings
// ---------------------------------------------------------------------------

/** Valid on every interpreter the tests accept (3.8+). */
const CLASSIC_FSTRINGS: Scenario = {
  name: "f-strings-valid-on-every-interpreter",
  module: py`"""f-strings that every supported interpreter accepts."""
width, precision, value, name = 10, 3, 3.14159, "ann"
data = {"key": "v", "w": 6}


def render():
    return [
        f"{name!r:>{width}}",
        f"{{literal}} {name}",
        f'{data["key"]}',
        f"{data['key']:>{data['w']}}",
        f"{value:{width}.{precision}f}",
        f"{'yes' if value > 3 else 'no'}",
        f"{(lambda x: x * 2)(21)}",
        f"{name=}",
        f"{value!s:.4}",
        f"{'}'}{'{'}",
        f"""{
            name
        } spans lines""",
        rf"\d{name}\{width}",
        f"{value:%>8.2f}",
        f"{3 != 4}",
        f"{name:{'<'}{width}}|",
        F"{name}" 'plain' f'{width}',
        f"\N{BULLET} {name}",
        f"{name}" if name else f"",
    ]


def run():
    return render()
`,
};

/** PEP 701 (Python 3.12): a replacement field is an ordinary expression. */
const PEP701_SOURCE = py`"""PEP 701 f-strings."""
items = ["a", "b"]
table = {"k": 1}
name = "ann"


def render():
    return [
        f"{"same quotes"}",
        f"{'\n'.join(items)}",
        f"{f"{f"{name}"}"}",
        f"{table["k"]}",
        f"{
            name  # a comment inside the field
        }",
        f"{"}"}",
        f"{name:{"<"}{10}}|",
        f'{'nested' + f'{name}'}',
        f"{"\\"}",
        f"{ {"a": 1}["a"] }",
        f"{name!r:^{len("xxxxxxxx")}}",
        f"{"a" if name else "b":>3}",
        f"""{"""triple inside triple"""}""",
    ]


def run():
    return render()
`;

// ---------------------------------------------------------------------------
// Finding 12: source encodings
// ---------------------------------------------------------------------------

/** One byte per character: lets a test spell out the exact bytes of a legacy-encoded file. */
const bytesOf = (text: string): Buffer => Buffer.from(text, "latin1");

const LATIN1_MODULE = bytesOf(
  '# -*- coding: latin-1 -*-\n"""Caf\xe9 module."""\nNAME = "Zo\xeb M\xfcller"\nPRICE = "\xa35 \xbd"\n\n\ndef run():\n    return [NAME, PRICE]\n',
);

const ENCODED_SCENARIOS: readonly Scenario[] = [
  { name: "latin-1-cookie", module: LATIN1_MODULE },
  {
    // 0x80..0x9f are printable in cp1252 (euro sign, curly quotes, dash) and controls in Latin-1.
    name: "cp1252-cookie",
    module: bytesOf(
      '# coding: cp1252\nTEXT = "\x80100 \x93quoted\x94 \x96 dash"\n\n\ndef run():\n    return TEXT\n',
    ),
  },
  {
    name: "gbk-cookie",
    module: bytesOf(
      '# -*- coding: gbk -*-\n"""\xd6\xd0\xce\xc4 doc."""\nGREETING = "\xc4\xe3\xba\xc3"\n\n\ndef run():\n    return GREETING\n',
    ),
  },
  {
    // Both characters end in byte 0x5c, the ASCII backslash.
    name: "shift-jis-cookie-with-0x5c-trail-bytes",
    module: bytesOf(
      '# -*- coding: shift_jis -*-\nKANA = "\x83\x5c\x95\x5c"\n\n\ndef run():\n    return [KANA, len(KANA)]\n',
    ),
  },
  {
    name: "cookie-on-second-line-after-shebang",
    module: bytesOf(
      '#!/usr/bin/env python3\n# vim: set fileencoding=iso-8859-15 :\nEURO = "\xa4"\n\n\ndef run():\n    return EURO\n',
    ),
  },
  {
    name: "utf-8-with-bom",
    module: Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from('"""Doc é."""\nSNAKE = "\u{1f40d} 東京"\n\n\ndef run():\n    return SNAKE\n', "utf8"),
    ]),
  },
  {
    name: "utf-8-with-bom-and-cookie",
    module: Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from('# coding: utf-8\nWORD = "naïve"\n\n\ndef run():\n    return WORD\n', "utf8"),
    ]),
  },
  {
    // Declares Latin-1 but holds only ASCII: the UTF-8 read of it is lossless.
    name: "latin-1-cookie-pure-ascii-read-as-text",
    module: '# -*- coding: latin-1 -*-\nVALUE = "plain"\n\n\ndef run():\n    return VALUE\n',
  },
];

/**
 * For every text codec of the local CPython that is ASCII-compatible, writes
 * modules whose string literal holds the codec's non-ASCII characters as raw
 * bytes (`S`) next to the same text as ASCII escapes (`E`).
 */
const CODEC_CASE_GENERATOR = py`import codecs, encodings, encodings.aliases, json, os, pkgutil, sys

out_dir = sys.argv[1]
spellings = json.loads(sys.argv[2])
ASCII = bytes(range(0x20, 0x7F))


def decodable(name):
    try:
        info = codecs.lookup(name)
        if not getattr(info, "_is_text_encoding", True):
            return None
        if info.decode(ASCII)[0] != ASCII.decode("ascii"):
            return None
        return info
    except Exception:
        return None


def units_of(info, name):
    """Every 1-, 2- (and for EUC-JP 3-) byte sequence that decodes to one non-ASCII character."""
    found = []

    def attempt(raw):
        try:
            text, consumed = info.decode(raw, "strict")
        except Exception:
            return False
        if consumed != len(raw) or len(text) != 1:
            return False
        point = ord(text)
        if point < 0x80 or 0xD800 <= point <= 0xDFFF:
            return False
        found.append((raw, text))
        return True

    for first in range(0x80, 0x100):
        if attempt(bytes([first])):
            continue
        for second in range(0x30, 0x100):
            attempt(bytes([first, second]))
    if name.startswith("euc_j"):
        for second in range(0xA1, 0xFF):
            for third in range(0xA1, 0xFF):
                attempt(bytes([0x8F, second, third]))
    return found


def escape(text):
    return "".join("\\U%08x" % ord(ch) for ch in text)


cases = []


def write_case(kind, cookie, label, units):
    if not units:
        return
    path = os.path.join(out_dir, "case_%04d.py" % len(cases))
    with open(path, "wb") as handle:
        handle.write(b"# -*- coding: " + cookie.encode("ascii") + b" -*-\n")
        handle.write(b'S = "' + b"".join(raw for raw, _ in units) + b'"\n')
        handle.write(b'E = "' + escape("".join(text for _, text in units)).encode("ascii") + b'"\n')
    cases.append({"kind": kind, "cookie": cookie, "label": label, "path": path, "characters": len(units)})


names = set(encodings.aliases.aliases.values())
names.update(module.name for module in pkgutil.iter_modules(encodings.__path__))
names.discard("aliases")
tables = {}
for name in sorted(names):
    info = decodable(name)
    if info is None:
        continue
    tables[name] = units_of(info, name)
    write_case("codec", name, name, tables[name])

for alias, target in sorted(encodings.aliases.aliases.items()):
    if target in tables:
        write_case("alias", alias, target, tables[target][:24])

for spelling in spellings:
    info = decodable(spelling)
    if info is None:
        continue
    canonical = None
    for name, units in tables.items():
        if codecs.lookup(name).name == info.name:
            canonical = name
            break
    if canonical is not None:
        write_case("spelling", spelling, canonical, tables[canonical][:24])

json.dump(cases, sys.stdout)
`;

/** Executes case modules; reports whether `S == E` (the bytes decoded to the right text). */
const CODEC_CASE_CHECKER = py`import codecs, io, json, sys, tokenize

with open(sys.argv[1], encoding="utf-8") as handle:
    paths = json.load(handle)

results = []
for path in paths:
    with open(path, "rb") as handle:
        data = handle.read()
    try:
        namespace = {"__name__": "codec_case"}
        exec(compile(data, path, "exec"), namespace)
        results.append({
            "equal": namespace["S"] == namespace["E"],
            "characters": len(namespace["S"]),
            "encoding": codecs.lookup(tokenize.detect_encoding(io.BytesIO(data).readline)[0]).name,
            "error": None,
        })
    except BaseException as exc:
        results.append({"equal": False, "characters": -1, "encoding": None, "error": "%s: %s" % (type(exc).__name__, exc)})

json.dump(results, sys.stdout)
`;

interface CodecCase {
  readonly kind: "codec" | "alias" | "spelling";
  readonly cookie: string;
  readonly label: string;
  readonly path: string;
  readonly characters: number;
}

interface CodecCheck {
  readonly equal: boolean;
  readonly characters: number;
  readonly encoding: string | null;
  readonly error: string | null;
}

/** Codecs the shield must be able to decode (CPython's codec module names). */
const REQUIRED_CODECS = [
  "cp1250",
  "cp1251",
  "cp1252",
  "cp437",
  "cp850",
  "cp932",
  "euc_jp",
  "euc_kr",
  "gb2312",
  "gbk",
  "iso8859_15",
  "iso8859_2",
  "koi8_r",
  "latin_1",
  "mac_roman",
  "shift_jis",
  "utf_8",
];

/** Spellings people actually write in coding cookies. */
const COOKIE_SPELLINGS = [
  "Latin-1",
  "latin1",
  "ISO-8859-1",
  "iso_8859_1",
  "ISO-8859-15",
  "windows-1252",
  "Windows-1251",
  "CP1252",
  "KOI8-R",
  "MacRoman",
  "GBK",
  "GB2312",
  "Shift_JIS",
  "sjis",
  "EUC-JP",
  "EUC-KR",
  "UTF-8",
  "utf8",
];

// ---------------------------------------------------------------------------
// Finding 15: .pyc weave
// ---------------------------------------------------------------------------

const PYC_SOURCE = `# -*- coding: utf-8 -*-
"""Módulo de prueba — ñ, 東京, \u{1f40d}."""
GREETING = "héllo wörld"
CJK = "東京タワー"
EMOJI = "\u{1f40d} snake"
MIXED = ("ascii", "café", b"\\xff\\xfe bytes", "naïve", 3.5, 10**30, -7, None, True, ...)
SURROGATE = "\\udc80lone"
LATIN1_RANGE = "\\xe9\\xe8\\xea"
LONG = "ü" * 300
PLAIN = "plain"


def greet(name="Zoë"):
    """Función: saluda a «name»."""
    suffix = "¡hola!"
    return suffix + " " + name + " " + GREETING


def nested():
    def inner(x="ß"):
        return x + "→" + CJK[:2]

    return inner() + (lambda: "λ")()


class Café:
    label = "étiquette"

    def m(self, sep=("·", "•")):
        return self.label + sep[0] + EMOJI


def run():
    return [
        GREETING, CJK, EMOJI, MIXED, SURROGATE, LATIN1_RANGE, len(LONG), PLAIN,
        greet(), nested(), Café().m(), greet.__doc__, __doc__,
    ]


print(ascii(run()))
`;

/**
 * Compares two .pyc files: what running them prints, and their code-object
 * trees. The second may only differ by extra code objects at the end of
 * `co_consts` (the woven decoys); every original constant must be equal in
 * value *and* type, and bytecode, names and line tables must be untouched.
 */
const PYC_COMPARATOR = py`import contextlib, io, json, marshal, sys, types

FIELDS = [
    "co_argcount", "co_kwonlyargcount", "co_nlocals", "co_stacksize", "co_flags", "co_code",
    "co_names", "co_varnames", "co_freevars", "co_cellvars", "co_filename", "co_name", "co_firstlineno",
]
for optional in ("co_posonlyargcount", "co_qualname", "co_linetable", "co_exceptiontable", "co_lnotab"):
    if hasattr(types.CodeType, optional) and optional != "co_lnotab":
        FIELDS.append(optional)


def load(path):
    with open(path, "rb") as handle:
        data = handle.read()
    return marshal.loads(data[16:])


def run(code):
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        exec(code, {"__name__": "__main__"})
    return captured.getvalue()


differences = []
decoys = []


def same_value(original, hardened, where):
    if type(original) is not type(hardened):
        differences.append("%s: type %s became %s" % (where, type(original).__name__, type(hardened).__name__))
    elif isinstance(original, types.CodeType):
        same_code(original, hardened, where + "/" + original.co_name)
    elif isinstance(original, (tuple, frozenset)):
        left = sorted(original, key=repr) if isinstance(original, frozenset) else list(original)
        right = sorted(hardened, key=repr) if isinstance(hardened, frozenset) else list(hardened)
        if len(left) != len(right):
            differences.append("%s: length %d became %d" % (where, len(left), len(right)))
        for index, (a, b) in enumerate(zip(left, right)):
            same_value(a, b, "%s[%d]" % (where, index))
    elif isinstance(original, str):
        if original.encode("utf-8", "surrogatepass") != hardened.encode("utf-8", "surrogatepass"):
            differences.append("%s: %s became %s" % (where, ascii(original), ascii(hardened)))
    elif original != hardened or repr(original) != repr(hardened):
        differences.append("%s: %r became %r" % (where, original, hardened))


def same_code(original, hardened, where):
    for field in FIELDS:
        if getattr(original, field) != getattr(hardened, field):
            differences.append("%s: %s changed" % (where, field))
    extra = hardened.co_consts[len(original.co_consts):]
    for index, (a, b) in enumerate(zip(original.co_consts, hardened.co_consts)):
        same_value(a, b, "%s.co_consts[%d]" % (where, index))
    if len(hardened.co_consts) < len(original.co_consts):
        differences.append("%s: constants were removed" % where)
    for value in extra:
        if isinstance(value, types.CodeType):
            decoys.append(value.co_name)
        else:
            differences.append("%s: a non-code constant was appended: %r" % (where, value))


original, hardened = load(sys.argv[1]), load(sys.argv[2])
same_code(original, hardened, "<module>")
json.dump({
    "differences": differences,
    "decoys": len(decoys),
    "original_stdout": run(original),
    "hardened_stdout": run(hardened),
}, sys.stdout)
`;

// ---------------------------------------------------------------------------
// Whole-file check against the standard library
// ---------------------------------------------------------------------------

/** Every other top-level module of the local standard library (about 80 real-world files). */
const STDLIB_LISTER = py`import json, os, sys

root = os.path.dirname(os.__file__)
paths = [
    os.path.join(root, name)
    for name in sorted(os.listdir(root))
    if name.endswith(".py") and os.path.getsize(os.path.join(root, name)) <= 300_000
]
json.dump(paths[::2], sys.stdout)
`;

/**
 * Proves that hardening changed nothing in the customer's program: after the
 * statements that mention an injected name are removed from the hardened AST,
 * it must be identical to the original AST (docstrings, future imports, every
 * expression, in order). Also compiles the hardened module, which is where
 * scope errors (a name used before its global declaration, ...) surface.
 */
const AST_PRESERVATION_CHECKER = py`import ast, json, sys

sys.setrecursionlimit(10000)
with open(sys.argv[1], encoding="utf-8") as handle:
    pairs = json.load(handle)


def module_names(tree):
    bound = set()
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(statement.name)
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            bound.update((alias.asname or alias.name).split(".")[0] for alias in statement.names)
        else:
            bound.update(
                node.id for node in ast.walk(statement)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            )
    return bound


def mentions(statement, names):
    if getattr(statement, "name", None) in names:
        return True
    for node in ast.walk(statement):
        if isinstance(node, ast.Name) and node.id in names:
            return True
        if isinstance(node, ast.alias) and (node.asname or node.name).split(".")[0] in names:
            return True
    return False


class StripInjected(ast.NodeTransformer):
    def __init__(self, names):
        self.names = names

    def generic_visit(self, node):
        super().generic_visit(node)
        for field in ("body", "orelse", "finalbody"):
            statements = getattr(node, field, None)
            if isinstance(statements, list):
                setattr(node, field, [
                    statement for statement in statements
                    if not (isinstance(statement, ast.stmt) and mentions(statement, self.names))
                ])
        return node


problems = []
for original_path, hardened_path in pairs:
    try:
        with open(original_path, "rb") as handle:
            original = ast.parse(handle.read(), original_path)
        with open(hardened_path, "rb") as handle:
            hardened_bytes = handle.read()
        hardened = ast.parse(hardened_bytes, hardened_path)
        compile(hardened_bytes, hardened_path, "exec", dont_inherit=True)
        injected = module_names(hardened) - module_names(original)
        if not injected:
            problems.append("%s: nothing was injected" % original_path)
            continue
        stripped = StripInjected(injected).visit(hardened)
        if ast.dump(stripped) != ast.dump(original):
            problems.append("%s: the customer's code changed" % original_path)
    except BaseException as exc:
        problems.append("%s: %s: %s" % (original_path, type(exc).__name__, exc))

json.dump({"problems": problems, "files": len(pairs)}, sys.stdout)
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("fuzz regression: Python source shield keeps the program's behaviour", () => {
  it.skipIf(!PY3)("07: the preamble does not bind `_` over gettext's builtin", () => {
    const [outcome] = expectSameBehaviour([GETTEXT_UNDERSCORE]);
    expect(outcome!.original.stdout).toBe(
      "Title Hello, ann\nTitle Hello, bob\nmodule binds _: False\n",
    );
  });

  it.skipIf(!PY3)("09: woven statements do not turn `_` into a function local", () => {
    const [outcome] = expectSameBehaviour([UNDERSCORE_IN_FUNCTIONS]);
    expect(outcome!.original.stdout.split("\n")[0]).toBe(
      "import 'Functions that use _ the way real code does.' ['<item>2', '<global>', 'inner:closure', [3, 'ac']]",
    );
  });

  it.skipIf(!PY3)("10: woven statements do not call a `hash` (or any builtin) the function or module rebinds", () => {
    expectSameBehaviour([BUILTIN_NAMES_AS_LOCALS, MODULE_REBINDS_HASH]);
  });

  it.skipIf(!PY3)("17: a module that shadows builtins still reloads", () => {
    expectSameBehaviour([MODULE_SHADOWS_BUILTINS]);
  });

  it.skipIf(!PY3)("17: no injected function uses a name the module has rebound, whatever the name", () => {
    const [outcome] = runScenarios([POISONED_BUILTINS]);
    expect(outcome!.original).toMatchObject({
      stdout: "5 8\ninjected functions exercised: False\n",
      error: null,
    });
    for (const [label, result] of outcome!.hardened) {
      expect(behaviour(result), label).toEqual({
        stdout: "5 8\ninjected functions exercised: True\n",
        error: null,
      });
    }
  });

  it.skipIf(!PY3)("07/10/17: injected code mentions no builtin by bare name and binds only generated names", () => {
    const [outcome] = expectSameBehaviour([STATIC_NAME_AUDIT]);
    expect(outcome!.original.stdout).toBe("[]\n['add', 'scale']\n");
  });

  it.skipIf(!PY3)("13: code is inserted at a logical-line boundary of the module prologue", () => {
    const outcomes = expectSameBehaviour(PROLOGUE_SCENARIOS);
    // The scenarios really exercise docstrings: __doc__ survived in each of them.
    const docstrings = outcomes.map(({ original }) => original.stdout.split("\n")[0]);
    expect(docstrings.filter((line) => line?.startsWith("import None")).length).toBe(3);
  });

  it.skipIf(!PY3)("13/18: woven statements go after the docstring expression, whatever form it takes", () => {
    expectSameBehaviour([FUNCTION_DOCSTRINGS]);
  });

  it.skipIf(!PY3)("20: f-strings every interpreter accepts are tokenised correctly", () => {
    expectSameBehaviour([CLASSIC_FSTRINGS]);
  });

  it("20: PEP 701 f-strings are accepted and left exactly as written", () => {
    const customerCode = PEP701_SOURCE.slice(PEP701_SOURCE.indexOf("items ="));
    for (const config of CONFIGS.filter((candidate) => !candidate.weaveDecoys)) {
      const hardened = protectPythonSource(PEP701_SOURCE, { intensity: config.intensity, seed: "fuzz-20" });
      expect(hardened.code.startsWith('"""PEP 701 f-strings."""\n')).toBe(true);
      expect(hardened.code.endsWith(customerCode)).toBe(true);
    }
    const woven = protectPythonSource(PEP701_SOURCE, { intensity: "maximum", seed: "fuzz-20", weaveDecoys: true });
    expect(woven.customerDefsWoven).toBe(2);
  });

  it.skipIf(!PY3 || !pythonAtLeast(3, 12))("20: PEP 701 f-strings behave the same after hardening (Python 3.12+)", () => {
    expectSameBehaviour([{ name: "pep-701-f-strings", module: PEP701_SOURCE }]);
  });
});

describe("fuzz regression: Python source encodings (finding 12)", () => {
  it.skipIf(!PY3)("legacy-encoded modules keep their strings and are re-declared as UTF-8", () => {
    const outcomes = expectSameBehaviour(ENCODED_SCENARIOS);
    for (const { scenario, hardened } of outcomes) {
      for (const [label, result] of hardened) {
        // What the file declares must be what its bytes are.
        expect(result.encoding, `${scenario.name} [${label}]`).toMatch(/^utf-8(-sig)?$/);
      }
    }
    const latin1 = outcomes[0]!;
    expect(latin1.original.encoding).toBe("iso-8859-1");
    expect(latin1.original.stdout.split("\n")[0]).toBe(
      "import 'Café module.' ['Zoë Müller', '£5 ½']",
    );
  });

  it("reports the encoding it decoded and maps the prologue offset back to bytes", () => {
    const gbk = bytesOf(
      '# -*- coding: gbk -*-\n"""\xd6\xd0\xce\xc4\xd6\xd0\xce\xc4"""\nIMPORT_MARKER = 1\n',
    );
    expect(protectPythonSource(gbk, { seed: "fuzz-12" }).sourceEncoding).toBe("gbk");
    expect(protectPythonSource(LATIN1_MODULE, { seed: "fuzz-12" }).sourceEncoding).toBe("latin-1");
    expect(protectPythonSource("X = 1\n", { seed: "fuzz-12" }).sourceEncoding).toBe("utf-8");
    // Four GBK characters are eight bytes: a character offset would fall short.
    expect(findPythonPrologueInsertionOffset(gbk).insertOffset).toBe(gbk.indexOf("IMPORT_MARKER"));
    const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("import os\n")]);
    expect(findPythonPrologueInsertionOffset(bom).insertOffset).toBe(3);
  });

  it("refuses a source it cannot decode faithfully instead of corrupting it", () => {
    const refuse = (source: string | Buffer, message: RegExp): void => {
      let thrown: unknown;
      try {
        protectPythonSource(source, { seed: "fuzz-12" });
      } catch (err) {
        thrown = err;
      }
      expect(thrown, String(message)).toBeInstanceOf(InvalidPythonSourceError);
      expect((thrown as Error).message).toMatch(message);
    };
    // The file was read as UTF-8 text: its non-ASCII bytes are already U+FFFD.
    refuse(LATIN1_MODULE.toString("utf8"), /read as UTF-8/);
    refuse(bytesOf('# coding: klingon\nX = "\xe9"\n'), /klingon/);
    refuse(bytesOf('# coding: ascii\nX = "\xe9"\n'), /not valid/);
    refuse(bytesOf('X = "\xe9"\n'), /not valid UTF-8/);
    refuse(bytesOf('# coding: euc-kr\nX = "\xff\xff"\n'), /not valid/);
    refuse(
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytesOf('# coding: latin-1\nX = "\xe9"\n')]),
      /BOM/,
    );
    // A codec known to CPython but not decodable here is fine while the file is ASCII ...
    expect(protectPythonSource(bytesOf('# coding: big5\nX = "plain"\n'), { seed: "fuzz-12" }).sourceEncoding).toBe("big5");
    // ... and refused as soon as it is not.
    refuse(bytesOf('# coding: big5\nX = "\xa4\x40"\n'), /big5/);
  });

  it("the engine never writes a hardened file whose strings differ from the source", () => {
    const dir = scratchDir("engine-latin1");
    const inputPath = join(dir, "app.py");
    const outputPath = join(dir, "app.hardened.py");
    writeFileSync(inputPath, LATIN1_MODULE);
    let refused = false;
    try {
      protectTarget({ inputPath, outputPath, intensity: "balanced", seed: "fuzz-12" });
    } catch {
      refused = true;
    }
    if (refused) {
      // Refusing is acceptable; leaving a corrupted file behind is not.
      expect(existsSync(outputPath)).toBe(false);
      return;
    }
    const written = readFileSync(outputPath).toString("utf8");
    expect(written).not.toContain("\uFFFD");
    expect(written).toContain('NAME = "Zoë Müller"');
    expect(written).not.toMatch(/coding[:=]\s*latin-1/);
  });

  it.skipIf(!PY3 || !pythonAtLeast(3, 9))(
    "decodes every supported codec, alias and cookie spelling exactly as the local CPython does",
    () => {
      const dir = scratchDir("codecs");
      const cases = runPythonJson<CodecCase[]>(CODEC_CASE_GENERATOR, [dir, JSON.stringify(COOKIE_SPELLINGS)]);
      expect(cases.length).toBeGreaterThan(100);

      const accepted: CodecCase[] = [];
      const hardenedPaths: string[] = [];
      for (const [index, codecCase] of cases.entries()) {
        let code: string;
        try {
          code = protectPythonSource(readFileSync(codecCase.path), {
            intensity: "stealth",
            seed: "fuzz-12",
          }).code;
        } catch (err) {
          // Declining a codec is safe; anything else is a bug.
          if (err instanceof InvalidPythonSourceError) continue;
          throw err;
        }
        const hardenedPath = join(dir, `hardened_${index}.py`);
        writeFileSync(hardenedPath, code, "utf8");
        accepted.push(codecCase);
        hardenedPaths.push(hardenedPath);
      }

      const manifest = join(dir, "paths.json");
      writeFileSync(manifest, JSON.stringify([...accepted.map((c) => c.path), ...hardenedPaths]), "utf8");
      const checks = runPythonJson<CodecCheck[]>(CODEC_CASE_CHECKER, [manifest]);
      accepted.forEach((codecCase, index) => {
        const where = `${codecCase.kind} ${codecCase.cookie} (${codecCase.label})`;
        // The generated original is self-consistent on this interpreter ...
        expect(checks[index], where).toMatchObject({ equal: true, characters: codecCase.characters, error: null });
        // ... and so must the hardened file be, now declaring UTF-8.
        expect(checks[accepted.length + index], where).toEqual({
          equal: true,
          characters: codecCase.characters,
          encoding: "utf-8",
          error: null,
        });
      });

      const acceptedCodecs = new Set(accepted.filter((c) => c.kind === "codec").map((c) => c.label));
      const available = new Set(cases.filter((c) => c.kind === "codec").map((c) => c.label));
      for (const codec of REQUIRED_CODECS.filter((name) => available.has(name))) {
        expect(acceptedCodecs.has(codec), `codec ${codec} must be supported`).toBe(true);
      }
      const acceptedSpellings = new Set(accepted.filter((c) => c.kind === "spelling").map((c) => c.cookie));
      const offeredSpellings = cases.filter((c) => c.kind === "spelling").map((c) => c.cookie);
      expect(offeredSpellings.length).toBeGreaterThanOrEqual(12);
      expect([...acceptedSpellings].sort()).toEqual([...offeredSpellings].sort());
      expect(accepted.filter((c) => c.kind === "alias").length).toBeGreaterThan(150);
    },
    180_000,
  );
});

describe("fuzz regression: .pyc weave keeps every constant (finding 15)", () => {
  it.skipIf(!PY3)("non-ASCII strings, bytes and nested code objects survive byte-exactly", () => {
    const dir = scratchDir("pyc");
    const sourcePath = join(dir, "consts.py");
    const originalPyc = join(dir, "consts.pyc");
    writeFileSync(sourcePath, PYC_SOURCE, "utf8");
    execFileSync(
      python3(),
      ["-I", "-B", "-c", "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)", sourcePath, originalPyc],
      { stdio: "pipe" },
    );
    const original = readFileSync(originalPyc);
    const layoutKnown = layoutForPycMagic(original.readUInt16LE(0)) !== null;

    for (const intensity of ["stealth", "balanced", "maximum", "bankrupt"] as const) {
      const hardened = protectPythonPycBuffer(original, { intensity, seed: "fuzz-15", weaveDecoys: true });
      const hardenedPyc = join(dir, `consts.${intensity}.pyc`);
      writeFileSync(hardenedPyc, hardened.buffer);
      const report = runPythonJson<{
        differences: string[];
        decoys: number;
        original_stdout: string;
        hardened_stdout: string;
      }>(PYC_COMPARATOR, [originalPyc, hardenedPyc]);

      expect(report.differences, intensity).toEqual([]);
      expect(report.hardened_stdout, intensity).toBe(report.original_stdout);
      expect(report.original_stdout).toContain("\\U0001f40d snake");
      if (layoutKnown) {
        expect(hardened.decoyCodeObjectsInjected, intensity).toBeGreaterThan(0);
        expect(report.decoys, intensity).toBe(hardened.decoyCodeObjectsInjected);
      }
    }
  });
});

describe("fuzz regression: hardening leaves the customer's code untouched", () => {
  it.skipIf(!PY3)(
    "standard-library modules: the hardened AST minus injected statements equals the original AST",
    () => {
      const dir = scratchDir("stdlib");
      const paths = runPythonJson<string[]>(STDLIB_LISTER, []);
      expect(paths.length).toBeGreaterThan(40);
      const intensities = ["stealth", "balanced", "maximum", "bankrupt"] as const;
      const pairs = paths.map((path, index) => {
        const hardened = protectPythonSource(readFileSync(path), {
          intensity: intensities[index % intensities.length]!,
          seed: `fuzz-stdlib-${index}`,
          weaveDecoys: true,
        });
        const hardenedPath = join(dir, `module_${index}.py`);
        writeFileSync(hardenedPath, hardened.code, "utf8");
        return [path, hardenedPath];
      });
      const manifest = join(dir, "pairs.json");
      writeFileSync(manifest, JSON.stringify(pairs), "utf8");
      const report = runPythonJson<{ problems: string[]; files: number }>(AST_PRESERVATION_CHECKER, [manifest]);
      expect(report.problems).toEqual([]);
      expect(report.files).toBe(paths.length);
    },
    240_000,
  );
});
