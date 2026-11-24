"""Conservative supplemental history scan; not a replacement for Gitleaks."""
import re
# Controlled Git inspection without a shell; no user-supplied commands.
import subprocess  # nosec B404

patterns = [rb"(?:gh[pousr]_[A-Za-z0-9]{30,})", rb"sk-[A-Za-z0-9_-]{30,}",
            rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", rb"AKIA[A-Z0-9]{16}",
            rb"C:[\\/]+Users[\\/]+", rb"/home/[a-z][a-z0-9_-]+/"]


def git(*args):
    # Fixed executable and argv, no shell; arguments originate from Git's tree.
    return subprocess.check_output(["git", *args], timeout=30)  # nosec B603, B607


commits = git("rev-list", "--all").decode().splitlines()
findings = []
for commit in commits:
    paths = git("ls-tree", "-r", "--name-only", commit).decode().splitlines()
    for path in paths:
        if path.startswith("private/") or path.endswith(".db") or path == ".env":
            findings.append((commit[:8], path, "forbidden path"))
        if path.endswith((".png", ".jpg", ".gif")):
            continue
        content = git("show", commit + ":" + path)
        if any(re.search(pattern, content) for pattern in patterns):
            findings.append((commit[:8], path, "sensitive pattern"))
if findings:
    for item in findings:
        print(*item)
    raise SystemExit(1)
print(f"Supplemental publication scan passed: {len(commits)} commits; no configured sensitive patterns found.")
