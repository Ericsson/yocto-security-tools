# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Ptest operations for CVE corrector."""
import os
import re
import sys
from typing import Optional

from .bitbake_ops import get_build_path
from .state import BuildPreexistingError
from .utils import logger, run_cmd, run_cmd_capture


def _kvm_available() -> bool:
    """Check whether KVM acceleration is usable on this build host.

    Mirrors the conditions ``runqemu`` itself enforces for its ``kvm``
    convenience option (see the Yocto Project dev-manual QEMU chapter):
    ``/dev/kvm`` must exist and be both readable and writable by the
    current user. Anything short of that (missing device node, running
    inside a container without ``/dev/kvm`` passed through, permission
    denied, etc.) means KVM acceleration is not usable and callers must
    fall back to full software emulation instead of asking ``runqemu``
    to enable an accelerator that will fail to initialize.

    Returns:
        True if ``/dev/kvm`` is present and both readable and writable.
    """
    kvm_dev = '/dev/kvm'
    return os.path.exists(kvm_dev) and os.access(kvm_dev, os.R_OK | os.W_OK)


def enable_ptest() -> None:
    """Enable ptest in local.conf if not already enabled."""
    build_path = get_build_path()
    local_conf = build_path / 'conf' / 'local.conf'
    result_distro = run_cmd_capture(['bitbake-getvar', 'DISTRO_FEATURES'], cwd=build_path)
    logger.debug("Current DISTRO_FEATURES: %s", result_distro.stdout.strip())
    if 'ptest' not in result_distro.stdout:
        logger.info("ptest not in DISTRO_FEATURES, appending to local.conf")
        with open(local_conf, 'a', encoding='utf-8') as f:
            f.write('DISTRO_FEATURES:append = " ptest"\n')
    else:
        logger.debug("ptest already in DISTRO_FEATURES, skipping")


def check_ptest_in_recipe(recipe: str) -> bool:
    """Check if ptest is enabled for recipe."""
    result = run_cmd_capture(['bitbake-getvar', '-r', recipe, "PTEST_ENABLED"])
    return 'PTEST_ENABLED="1"' in result.stdout


def run_ptest(recipe: str, build_timeout: int = 7200,
              test_timeout: int = 3600) -> Optional[str]:
    """Run ptest and return results summary.

    Args:
        recipe: Recipe name to test.
        build_timeout: Timeout in seconds for image build (default 2h).
        test_timeout: Timeout in seconds for testimage run (default 1h).
    """
    if not check_ptest_in_recipe(recipe):
        print(f"Recipe {recipe} does not have ptest enabled")
        return None

    build_path = get_build_path()
    local_conf = build_path / 'conf' / 'local.conf'

    # Save original content for cleanup
    _original_conf = local_conf.read_text() if local_conf.exists() else None

    # KVM acceleration is opportunistic: only ask runqemu to enable it when
    # /dev/kvm is actually usable. Requesting "kvm" on a host without a
    # working accelerator (no /dev/kvm, no VT-capable CPU, container
    # without the device passed through, etc.) makes runqemu fail outright
    # instead of quietly falling back to software emulation, so the token
    # is only added when _kvm_available() confirms it will work.
    qemuparams = 'slirp nographic'
    if _kvm_available():
        qemuparams += ' kvm'
        logger.debug("KVM is available, enabling KVM acceleration for testimage")
    else:
        logger.info(
            "KVM not usable (/dev/kvm missing or not read/write-accessible), "
            "falling back to software emulation for testimage")

    result_inherit = run_cmd_capture(
        ['bitbake-getvar', 'IMAGE_CLASSES', '-r', 'core-image-minimal'])
    if 'testimage' not in result_inherit.stdout and local_conf.exists():
        with open(local_conf, 'a', encoding='utf-8') as f:
            f.write('\n## Added by CVE corrector (test-only, auto-removed)\n')
            f.write(f'\nTEST_RUNQEMUPARAMS += "{qemuparams}"\n')
            # WARNING: These features weaken security. They are required
            # for automated testimage/ptest execution only.
            f.write('\nEXTRA_IMAGE_FEATURES += "allow-empty-password empty-root-password allow-root-login"\n')
            f.write('IMAGE_CLASSES += "testimage"\n')
            f.write('SERIAL_CONSOLES = "115200;ttyS0"\n')
            f.write('TEST_QEMUBOOT_TIMEOUT = "60"\n')
            f.write('QB_MEM = "-m 2048"\n')
            f.write('TEST_SUITES += "ping ssh ptest"\n')

    result_suites = run_cmd_capture(
        ['bitbake-getvar', 'TEST_SUITES', '-r', 'core-image-minimal'])
    if 'ptest' not in result_suites.stdout:
        with open(local_conf, 'a', encoding='utf-8') as f:
            f.write('\n## Added by CVE corrector - ptest suite\n')
            f.write('TEST_SUITES += "ping ssh ptest"\n')

    content = local_conf.read_text()
    lines = content.splitlines(keepends=True)
    updated = False
    for i, line in enumerate(lines):
        if line.startswith('CORE_IMAGE_EXTRA_INSTALL'):
            lines[i] = f'CORE_IMAGE_EXTRA_INSTALL = "{recipe}-ptest openssh-sshd"\n'
            updated = True
            break
    if updated:
        local_conf.write_text(''.join(lines))
    else:
        with open(local_conf, 'a', encoding='utf-8') as f:
            f.write(f'CORE_IMAGE_EXTRA_INSTALL = "{recipe}-ptest openssh-sshd"\n')

    print("Building test image...")
    _failed = False
    try:
        if run_cmd(['bitbake', 'core-image-minimal'], timeout=build_timeout) != 0:
            print("bitbake build failed", file=sys.stderr)
            _failed = True
            raise BuildPreexistingError("Test image build failed")

        print("Running testimage...")
        rc = run_cmd(['bitbake', 'core-image-minimal', '-c', 'testimage'],
                     timeout=test_timeout)
        if rc != 0:
            _failed = True
    finally:
        # On failure, preserve the test-modified local.conf for debugging
        if _failed and _original_conf is not None:
            debug_conf = local_conf.with_suffix('.conf.ptest-debug')
            debug_conf.write_text(local_conf.read_text())
            logger.info(
                "Preserved test-modified local.conf for debugging: %s",
                debug_conf,
            )
        # Restore original local.conf to remove insecure test features
        if _original_conf is not None:
            local_conf.write_text(_original_conf)

    if rc == -1:
        print(f"testimage timed out after {test_timeout}s", file=sys.stderr)
        return None

    ptest_logs = list((build_path / 'tmp-glibc').glob(
        f'work/*/core-image-minimal/*/testimage/ptest_log*/{recipe}'))
    if not ptest_logs:
        ptest_logs = list((build_path / 'tmp').glob(
            f'work/*/core-image-minimal/*/testimage/ptest_log*/{recipe}'))
    if ptest_logs:
        log_file = sorted(ptest_logs)[-1]
        content = log_file.read_text()
        # The per-recipe log doesn't contain the STOP: ptest-runner marker —
        # that lives in the ptest-runner.log alongside it.  Check the runner
        # log so summarize_ptest_log can distinguish a complete run from a
        # truncated one.
        runner_log = log_file.parent / 'ptest-runner.log'
        if runner_log.exists():
            runner_content = runner_log.read_text()
            if 'STOP: ptest-runner' in runner_content:
                content += '\nSTOP: ptest-runner\n'
        return summarize_ptest_log(content)
    return None


# Per the ptest-runner result-line convention (test-manual/ptest.rst):
# "result: testname" where result is PASS, FAIL, or SKIP. Anchored to the
# start of the line (optional leading whitespace) so that unrelated text
# elsewhere on the line — e.g. the aggregate "STOP: ptest-runner" /
# "TOTAL: 1 FAIL: 2" summary lines ptest-runner prints at the end of a
# run — is never mistaken for an individual test result.
#
# ptest-runner.log uses "PASS:", "FAIL:", "SKIP:" while the per-recipe
# log file uses "PASSED:", "FAILED:", "SKIPPED:" — match both variants.
_RESULT_LINE_RE = re.compile(r'^\s*(PASS(?:ED)?|FAIL(?:ED)?|SKIP(?:PED)?):\s*(.+)$')

# A test run that never reaches a PASS/FAIL/SKIP result line because the
# runner killed it (e.g. it hung and hit the per-test timeout) instead
# reports a "TIMEOUT: <path>" marker line naming the ptest that was
# killed. ptest-runner also prints "ERROR: Exited from signal Killed (9)"
# immediately before it, but that is context/detail about *why* the test
# was killed, not a second aborted test — counting both would double the
# aborted tally for a single kill.
_ABORTED_MARKER = 'TIMEOUT:'


def summarize_ptest_log(content: str) -> str:
    """Summarize a ptest log's PASS/FAIL/SKIP result lines.

    Individual ptest result lines follow the Automake-style convention
    documented for ptest-runner: ``result: testname`` where ``result`` is
    one of ``PASS``, ``FAIL``, or ``SKIP``.

    A test that is killed (e.g. by the per-test timeout) never emits a
    PASS/FAIL/SKIP result line at all — it is reported via a ``TIMEOUT:
    <path>`` marker line instead (ptest-runner also logs an "ERROR: Exited
    from signal Killed (9)" line right before it, but that is
    context/detail about the kill, not a second test). Such tests are
    counted separately as "aborted" so they are not silently treated as
    passing (zero failures) just because no FAIL: line was emitted for
    them.

    The overall run is only considered complete if it reaches
    ``STOP: ptest-runner`` — a run that never finishes (e.g. the QEMU
    instance crashed or the whole testimage task was itself killed before
    ptest-runner could print its final summary) has a truncated, unreliable
    PASS/FAIL/SKIP count and must not be reported as if it were a normal
    clean result.

    Args:
        content: Raw ptest log content.

    Returns:
        Human-readable summary string, e.g.
        ``"PASSED: 10, FAILED: 1, SKIPPED: 0, ABORTED: 1"``. Prefixed with
        a warning if the run never reached ``STOP: ptest-runner``.
    """
    passed = 0
    failed = 0
    skipped = 0
    failing: list[str] = []

    for line in content.splitlines():
        match = _RESULT_LINE_RE.match(line)
        if not match:
            continue
        result, name = match.group(1), match.group(2).strip()
        if result.startswith('PASS'):
            passed += 1
        elif result.startswith('FAIL'):
            failed += 1
            failing.append(name)
        elif result.startswith('SKIP'):
            skipped += 1

    aborted = sum(1 for line in content.splitlines() if line.startswith(_ABORTED_MARKER))
    finished = any(line.startswith('STOP: ptest-runner') for line in content.splitlines())

    summary = f"PASSED: {passed}, FAILED: {failed}, SKIPPED: {skipped}, ABORTED: {aborted}"
    if not finished:
        summary = (
            "WARNING: ptest-runner did not reach STOP: ptest-runner — the "
            "run was cut short and this summary is incomplete/unreliable.\n"
            + summary
        )
    if failing:
        summary += '\nFailing cases:\n' + '\n'.join(f'  {c}' for c in failing)
    return summary


def compare_ptest_results(before: str, after: str) -> bool:
    """Compare ptest results, return True if failures did not increase.

    Both failed tests (``FAILED:``) and aborted/killed tests (``ABORTED:``,
    e.g. a test that hit the per-test timeout and was never able to report
    a result) are treated as regressions if their count increases — a test
    that used to complete and now hangs is a regression even though it
    never emits a FAIL: line.

    If the *after* run never reached ``STOP: ptest-runner`` (flagged by the
    ``WARNING:`` prefix ``summarize_ptest_log`` adds), its PASS/FAIL counts
    are unreliable/incomplete and must not be trusted to declare "no
    regression" — this is treated as a regression so it gets investigated
    rather than silently accepted.
    """
    if after.startswith('WARNING:'):
        return False

    before_match = re.search(r'PASSED: (\d+), FAILED: (\d+)(?:, SKIPPED: \d+, ABORTED: (\d+))?', before)
    after_match = re.search(r'PASSED: (\d+), FAILED: (\d+)(?:, SKIPPED: \d+, ABORTED: (\d+))?', after)
    if before_match and after_match:
        before_bad = int(before_match.group(2)) + int(before_match.group(3) or 0)
        after_bad = int(after_match.group(2)) + int(after_match.group(3) or 0)
        return after_bad <= before_bad
    return True
