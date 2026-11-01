"""Pin the organization defaults: the security gate template, the default SECURITY.md, CODEOWNERS and the profile.

No file of this public repository names another organization repository; the complete check against the inventory
runs privately.
"""
import json
import os
import re
import tempfile
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
TEMPLATES = os.path.join(ROOT, "workflow-templates")
POLICY_URL = "https://github.com/strangebasisdevs/strange_security/blob/main/docs/ORG_BASELINE.md"
SECURITY_GATE_SHA = "b3a6732ecbe1796fb2e7eaeedb228c705962db44"


def read_file(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8", newline="") as handle:
        return handle.read().replace("\r\n", "\n")


def active(text):
    """The lines of a YAML or CODEOWNERS file that are not blank and not full-line comments."""
    return [line for line in text.split("\n") if line.strip() and not line.lstrip().startswith("#")]


USES = re.compile(
    r"^\s*uses:\s*strangebasisdevs/strange_security/\.github/workflows/(?P<name>[a-z]+)\.yml"
    r"@(?P<sha>[0-9a-f]{40}) # v(?P<version>\d+\.\d+\.\d+)\s*$"
)


# The two ways of writing the same trigger: the block list and the flow list.
TRIGGER_FORMS = (
    ["  pull_request:", "  push:", "    branches:", "      - $default-branch"],
    ["  pull_request:", "  push:", "    branches: [$default-branch]"],
)


def trigger_block(text):
    """The lines under the top-level on: key, or None when there is none."""
    on = re.search(r"^on:\n((?:[ ]+\S.*\n)+)", text, re.M)
    return on.group(1).splitlines() if on else None


class SecurityGateTemplateTest(unittest.TestCase):
    def setUp(self):
        self.text = read_file("workflow-templates", "security_gate.yml")
        self.lines = active(self.text)

    def test_every_reference_is_a_full_sha_with_release_comment(self):
        uses = [line for line in self.lines if re.match(r"^\s*(?:-\s+)?[\"']?uses[\"']?\s*:", line)]
        self.assertEqual(len(uses), 3, uses)
        names = []
        for line in uses:
            match = USES.match(line)
            self.assertIsNotNone(match, "not pinned by a 40-hex SHA and '# vX.Y.Z': %r" % line)
            self.assertEqual(match.group("sha"), SECURITY_GATE_SHA, line)
            self.assertEqual(match.group("version"), "1.2.1", line)
            names.append(match.group("name"))
        self.assertEqual(sorted(names), ["gitleaks", "semgrep", "trivy"])
        for line in self.lines:
            self.assertNotRegex(line, r"@(main|master)\b", "mutable reference on an active line: %r" % line)

    def test_permissions(self):
        block = re.search(r"^permissions:\n((?:[ ]{2}\S.*\n)+)", self.text, re.M)
        self.assertIsNotNone(block, "no top-level permissions block")
        granted = sorted(line.strip() for line in block.group(1).splitlines())
        self.assertEqual(granted, ["actions: read", "contents: read", "security-events: write"])

    def test_permissions_are_granted_only_at_the_top_level(self):
        grants = [line for line in self.lines if re.match(r"^\s*[\"']?permissions[\"']?\s*:", line)]
        self.assertEqual(grants, ["permissions:"], "a job-level or repeated permissions key widens the grant")

    def test_top_level_keys(self):
        keys = [re.match(r"^([^\s:]+):", line).group(1) for line in self.lines if re.match(r"^[^\s:]+:", line)]
        self.assertEqual(sorted(keys), ["jobs", "name", "on", "permissions"])

    def test_exactly_three_jobs_that_only_call_a_workflow(self):
        jobs = {}
        current = None
        field_name = None
        in_jobs = False
        for line in self.lines:
            if re.match(r"^\S", line):
                in_jobs = line == "jobs:"
                continue
            if not in_jobs:
                continue
            job = re.match(r"^  ([^\s:]+):\s*$", line)
            field = re.match(r"^    ([^\s:]+):", line)
            if job:
                current = jobs.setdefault(job.group(1), {})
                field_name = None
            elif field:
                self.assertIsNotNone(current, line)
                field_name = field.group(1)
                current[field_name] = []
            else:
                self.assertTrue(line.startswith("      "), "unexpected indentation: %r" % line)
                self.assertEqual(field_name, "with", "only 'with:' may have children: %r" % line)
                current[field_name].append(line.strip())
        self.assertEqual(sorted(jobs), ["gitleaks", "semgrep", "trivy"])
        for name, fields in jobs.items():
            self.assertLessEqual(set(fields), {"name", "uses", "with"}, "job %s has extra keys" % name)
            self.assertLessEqual({"name", "uses"}, set(fields), "job %s lacks name or uses" % name)

    def test_triggers_use_the_default_branch_placeholder(self):
        self.assertIn(trigger_block(self.text), TRIGGER_FORMS)
        self.assertNotRegex("\n".join(self.lines), r"(?m)^\s*-\s+main\s*$", "template must use the placeholder")
        self.assertNotRegex("\n".join(self.lines), r"branches:.*\bmain\b", "template must use the placeholder")

    def test_both_trigger_forms_are_accepted_and_main_is_not(self):
        for form in TRIGGER_FORMS:
            self.assertIn(trigger_block("name: x\non:\n" + "\n".join(form) + "\njobs: {}\n"), TRIGGER_FORMS)
        for branch in ("    branches: [main]", "    branches:\n      - main"):
            text = "on:\n  pull_request:\n  push:\n" + branch + "\n"
            self.assertNotIn(trigger_block(text), TRIGGER_FORMS, branch)

    def test_header_says_where_the_pin_update_comes_from(self):
        header = " ".join(line.lstrip("# ") for line in self.text.split("\n") if line.startswith("#"))
        self.assertIn("when .github/dependabot.yml has a github-actions entry", header)

    def test_job_names(self):
        jobs = dict(re.findall(r"^  (semgrep|trivy|gitleaks):\n    name: (\S+)$", self.text, re.M))
        self.assertEqual(jobs, {"semgrep": "Semgrep", "trivy": "Trivy", "gitleaks": "Gitleaks"})
        self.assertIn("name: Security gate\n", self.text)


class PropertiesTest(unittest.TestCase):
    def props(self):
        return json.loads(read_file("workflow-templates", "security_gate.properties.json"))

    def test_properties_parse_and_describe_the_template(self):
        self.assertTrue(os.path.isfile(os.path.join(TEMPLATES, "security_gate.yml")))
        self.assertEqual(
            self.props(),
            {
                "name": "Security gate (strange_security)",
                "description": "Semgrep, Trivy filesystem and Gitleaks history scans from "
                "strangebasisdevs/strange_security, pinned by commit SHA",
                "iconName": "shield",
                "categories": ["Security"],
            },
        )

    def test_icon_names_an_existing_svg(self):
        icon = self.props()["iconName"] + ".svg"
        self.assertTrue(os.path.isfile(os.path.join(TEMPLATES, icon)), "iconName has no matching svg: " + icon)
        self.assertIn("<svg", read_file("workflow-templates", icon))


class SecurityPolicyTest(unittest.TestCase):
    def setUp(self):
        self.text = read_file("SECURITY.md")

    def test_no_template_header(self):
        self.assertTrue(self.text.startswith("# Security policy\n\n## Supported versions\n"), "no added intro")
        self.assertNotIn("<!--", self.text)
        self.assertNotIn("What to change", self.text)

    def test_names_the_security_tab(self):
        self.assertIn("Security tab", self.text)
        self.assertIn("Report a vulnerability", self.text)

    def test_generic_scope(self):
        self.assertIn(
            "the code in the repository you are viewing and the release artifacts it publishes",
            " ".join(self.text.split()),
        )
        self.assertNotIn("Replace this section", self.text)

    def test_required_sections(self):
        for heading in ("Supported versions", "Reporting a vulnerability", "What to expect", "Scope"):
            self.assertRegex(self.text, r"(?m)^## %s$" % heading)


class CodeownersTest(unittest.TestCase):
    def test_default_rule(self):
        self.assertEqual(active(read_file(".github", "CODEOWNERS")), ["* @strangebasis"])


class ProfileTest(unittest.TestCase):
    def test_one_paragraph_with_one_link_to_the_policy(self):
        text = read_file("profile", "README.md").strip()
        self.assertNotIn("\n\n", text, "the profile is one paragraph")
        self.assertEqual(re.findall(r"https?://[^)\s]+", text), [POLICY_URL])
        self.assertNotRegex(text, r"\d", "no digits")
        self.assertNotRegex(text, r"(?m)^\s*([-*]|\d+\.)\s", "no repository list")

    def test_root_readme_points_at_profile_and_policy(self):
        text = read_file("README.md")
        self.assertIn("(profile/README.md)", text)
        self.assertIn(POLICY_URL, text)
        self.assertLessEqual(len([line for line in text.split("\n") if line.strip()]), 3)


# The repository is public: it names no organization repository other than strange_security and itself.
# The test below carries only the organization-prefix detector: any token that starts with the organization
# prefix and is not an allowed token is a finding, which also catches misspellings and repositories created
# later. The complete check against the inventory runs privately. The scan covers every file of the working tree
# except the top-level .git directory or file, this test file and its bytecode included, so the prefix is built at
# run time below (a join of two parts, which the compiler does not fold into one constant) and fixtures are built
# from fictional names. Matching is case-insensitive and sees through Markdown escapes, width variants and
# zero-width characters.
PREFIX = "".join(("str", "ange"))
ALLOWED_TOKENS = (PREFIX + "basisdevs", PREFIX + "_security", PREFIX + "basis")
TOKEN_PATTERN = re.compile(r"[a-z0-9_-]+")
ZERO_WIDTH = re.compile("[\u00ad\u200b-\u200f\u2060\ufeff]")


def normalise(text):
    """Fold what hides a name from a plain search: width and case variants, Markdown escapes, zero-width characters."""
    text = ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))
    return text.replace("\\", "").lower()


def findings(name, text):
    """Findings as "name:line: token" for every token that carries the organization prefix and is not allowed.

    A token is a maximal run of [a-z0-9_-]; every other character, "/" and "@" included, separates tokens. The prefix
    applies at the start of a token (so right after "@" or "/") and after a "-" or "_" inside it, so a prefixed name
    glued to another word with "-" or "_" is found, as is one that is followed by a suffix. The organization, the
    sibling policy repository and the owner's public handle are allowed, but only as the whole token.
    """
    found = []
    for number, line in enumerate(text.split("\n"), 1):
        for match in TOKEN_PATTERN.finditer(normalise(line)):
            token = match.group(0).strip("-_")
            if token in ALLOWED_TOKENS:
                continue
            starts = [0] + [i + 1 for i, char in enumerate(token) if char in "-_"]
            if any(token.startswith(PREFIX, start) for start in starts):
                found.append("%s:%d: %s" % (name, number, token))
    return found


def scanned_files(root=ROOT):
    """Every file of the working tree except the top-level .git, as "/" separated paths relative to root."""
    paths = []
    for directory, subdirectories, files in os.walk(root):
        if directory == root:
            subdirectories[:] = [d for d in subdirectories if d != ".git"]
            files = [f for f in files if f != ".git"]
        paths += [os.path.relpath(os.path.join(directory, f), root).replace(os.sep, "/") for f in files]
    return sorted(paths)


def scan(root=ROOT):
    """Findings in the path and in the text of every scanned file under root."""
    found = []
    for path in scanned_files(root):
        found += findings(path, path)
        with open(os.path.join(root, *path.split("/")), "rb") as handle:
            found += findings(path, handle.read().decode("utf-8", "replace").replace("\r\n", "\n"))
    return found


class PublicNamesTest(unittest.TestCase):
    def test_every_file_names_no_other_repository(self):
        paths = scanned_files()
        for expected in ("README.md", "SECURITY.md", "workflow-templates/shield.svg", "tests/test_defaults.py"):
            self.assertIn(expected, paths, "the scan must cover every file")
        self.assertEqual(scan(), [])

    def test_prefix_detector(self):
        self.assertTrue(findings("x", "see " + PREFIX.title() + "\\_Widget here"))
        self.assertTrue(findings("x", ALLOWED_TOKENS[0] + "/" + PREFIX + "_example_repo"))
        self.assertTrue(findings("x", PREFIX[:3] + "\u200b" + PREFIX[3:] + "_widget"))
        self.assertTrue(findings("x", "".join(chr(ord(c) + 0xFEE0) for c in PREFIX) + "_widget"))
        self.assertEqual(findings("x", ALLOWED_TOKENS[0] + "/" + ALLOWED_TOKENS[1] + " and @" + ALLOWED_TOKENS[2]), [])

    def test_prefix_detector_sees_glued_and_adjacent_names(self):
        name = PREFIX + "_example_repo"
        for text in (
            "@" + name,
            "-" + name,
            "my-" + name,
            "my_" + name,
            name + "-suffix",
            name + "_suffix",
            "my-" + ALLOWED_TOKENS[2],
            ALLOWED_TOKENS[2] + "-extra",
            ALLOWED_TOKENS[1] + "_extra",
            "@" + PREFIX + "-example-repo",
            "org/" + name + ".git",
            PREFIX + "&#95;example",
            PREFIX + "%5Fexample",
            "see " + PREFIX + " here",
        ):
            self.assertTrue(findings("x", text), text)
        self.assertEqual(findings("x", PREFIX + "\\_example_repo"), ["x:1: " + name])

    def test_prefix_detector_allows_only_the_whole_allowed_tokens(self):
        for text in (
            "@" + ALLOWED_TOKENS[2],
            "`" + ALLOWED_TOKENS[1] + "`",
            "(" + ALLOWED_TOKENS[1] + ")",
            ALLOWED_TOKENS[0] + "/" + ALLOWED_TOKENS[1] + "/.github",
            "* @" + ALLOWED_TOKENS[2],
            "no prefixed name here",
        ):
            self.assertEqual(findings("x", text), [], text)

    def test_scan_uses_slash_separated_paths(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "docs", "deep"))
            with open(os.path.join(root, "docs", "deep", PREFIX + "_example_repo.md"), "w", encoding="utf-8") as handle:
                handle.write("nothing to see\n")
            self.assertEqual(scanned_files(root), ["docs/deep/" + PREFIX + "_example_repo.md"])
            found = scan(root)
            self.assertEqual(len(found), 1, found)
            self.assertTrue(found[0].startswith("docs/deep/" + PREFIX + "_example_repo.md:1: "), found)

    def test_scan_covers_everything_except_the_top_level_git(self):
        name = PREFIX + "_example_repo"
        with tempfile.TemporaryDirectory() as root:
            for directory in (".git", "__pycache__", os.path.join("sub", ".git")):
                os.makedirs(os.path.join(root, directory))
                with open(os.path.join(root, directory, "data"), "w", encoding="utf-8") as handle:
                    handle.write(name + "\n")
            self.assertEqual(scanned_files(root), ["__pycache__/data", "sub/.git/data"])
            self.assertEqual(len(scan(root)), 2)
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, ".git"), "w", encoding="utf-8") as handle:
                handle.write("gitdir: elsewhere/" + name + "\n")
            self.assertEqual(scanned_files(root), [])


if __name__ == "__main__":
    unittest.main()
