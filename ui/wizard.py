"""OSINT EYE - Interactive Wizard

Guided setup that runs fully offline and returns a list of CLI arguments
consumed by ``osint_eye.py``'s argparse parser. The first element is the
positional target (NOT the program name); every flag emitted here exists in
the parser: --depth, --stealth, --no-ai, --no-cache, --rich, --output,
--agent, --pdf, --dashboard, --export-cypher.

The wizard also asks for scope/exclusions and requires an explicit
authorization confirmation before any scan starts: targets that fall
outside the scope (or inside the exclusions) are dropped right here, so
the positional arguments passed to the CLI already respect the user's
declared scope. Domain/wildcard/CIDR matching lives in ``_matches_scope``
so the CLI-side enforcement (scope-file) can reuse the same semantics.
"""

import ipaddress
import sys
from fnmatch import fnmatch

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.text import Text

try:  # package import (python osint_eye.py) / direct script import fallback
    from ui.rich_cli import RichCLI
except ImportError:  # pragma: no cover - direct execution
    from rich_cli import RichCLI

console = Console()

# Flags accepted by osint_eye.py's argparse — keep in sync when it changes.
_VALID_FLAGS = {
    "--depth", "--stealth", "--no-ai", "--no-cache", "--rich", "--output",
    "--agent", "--pdf", "--dashboard", "--export-cypher", "--modules",
    "--profile", "--diff", "--monitor", "--monitor-interval", "--webhook",
    "--plugin-dir",
}


class InteractiveWizard:
    """CLI wizard to guide users through OSINT EYE setup interactively."""

    def __init__(self):
        self.cli = RichCLI()

    # ── helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _looks_like_url(token: str) -> bool:
        """Whether ``token`` smells like a URL instead of a bare target.

        Detects explicit schemes (``https://…``), scheme-less forms with a
        path (``example.com/admin``), userinfo (``user@host``), bracketed
        hosts (``[::1]:8080``) and ``host:port`` (``example.com:8080``).
        Bare IPv6 (``::1``, ``2001:db8::1``) is NOT flagged: several colons
        without a digits-only port is how IPv6 looks.
        """
        t = (token or "").strip().lower()
        if not t:
            return False
        if "://" in t or "@" in t:
            return True
        if t.startswith("[") or "]" in t:
            return True
        if "/" in t:  # a valid CIDR is NOT a URL
            try:
                ipaddress.ip_network(t, strict=False)
                return False
            except ValueError:
                return True
        if t.count(":") == 1:  # host:port — bare IPv6 has 2+ colons
            host, _, port = t.partition(":")
            if host and port.isdigit():
                return True
        return False

    @staticmethod
    def _host_from_url(token: str) -> str:
        """Best-effort host extraction from a URL-ish token.

        ``https://EXAMPLE.com/admin?t=1`` → ``EXAMPLE.com``;
        ``user@host`` → ``host``; ``[::1]:8080`` → ``::1``;
        ``example.com:8080`` → ``example.com``. Returns ``''`` when
        nothing host-like can be extracted.
        """
        t = (token or "").strip()
        if "://" in t:
            t = t.split("://", 1)[1]
        t = t.split("/", 1)[0]
        t = t.split("@", 1)[-1]
        if t.startswith("[") and "]" in t:  # [v6]:port form
            host, _, _rest = t[1:].partition("]")
            return host
        host, _, _port = t.partition(":")
        return host or t

    @classmethod
    def _validate_target(cls, target: str):
        """Validate one scan target format.

        Returns ``(ok, reason)``. Accepted formats: domain names
        (``scanme.example.org``, punycode ``xn--…`` labels included),
        IPv4/IPv6 addresses and CIDR networks (``192.0.2.0/24``).
        Wildcards are rejected for targets — they belong in scope/
        exclusions — as are URL-like or padded inputs.
        """
        t = (target or "").strip().rstrip(".").lower()
        if not t:
            return False, "empty target"
        if "*" in t or "?" in t:
            return False, "wildcards are not scan targets — put them in scope/exclusions"
        if "://" in t or "@" in t or " " in t or "[" in t or "]" in t:
            return False, f"'{t}' is not a bare domain, IP or CIDR"

        # CIDR (must contain exactly one '/'); ip_network also rejects
        # things like 'example.com/24' for us.
        if "/" in t:
            try:
                ipaddress.ip_network(t, strict=False)
                return True, ""
            except ValueError:
                return False, f"'{t}' is not a valid CIDR (e.g. 192.0.2.0/24)"

        # IP address (v4 or v6)?
        try:
            ipaddress.ip_address(t)
            return True, ""
        except ValueError:
            pass

        # Domain name (RFC-style labels; a-z, 0-9 and '-', punycode included)
        if len(t) > 253:
            return False, "domain longer than 253 characters"
        for label in t.split("."):
            if not label:
                return False, "empty label (double dot?)"
            if len(label) > 63:
                return False, f"label '{label}' longer than 63 characters"
            if label.startswith("-") or label.endswith("-"):
                return False, f"label '{label}' starts/ends with hyphen"
            if not set(label) <= set("abcdefghijklmnopqrstuvwxyz0123456789-"):
                return False, f"label '{label}' has characters outside a-z, 0-9 and '-'"
        return True, ""

    @classmethod
    def _validate_targets(cls, tokens: list):
        """Validate a batch of raw tokens.

        Returns ``(clean, bad)``: ``clean`` keeps the valid tokens in
        order, ``bad`` holds ``(token, reason)`` pairs for the rest.
        URL-like tokens fail here with a dedicated reason — the
        interactive swap lives in ``_ask_targets``.
        """
        clean, bad = [], []
        for token in tokens:
            if cls._looks_like_url(token):
                bad.append((token, "looks like a URL — use the bare host"))
                continue
            ok, reason = cls._validate_target(token)
            if ok:
                clean.append(token)
            else:
                bad.append((token, reason))
        return clean, bad

    @staticmethod
    def _parse_targets(raw: str) -> list:
        """Accept 'a.com, b.com  c.com' → ['a.com', 'b.com', 'c.com']."""
        for sep in (",", " "):
            raw = raw.replace(sep, "\n")
        seen, targets = set(), []
        for token in (t.strip() for t in raw.split("\n")):
            token = token.rstrip("/")
            if token and token not in seen:
                seen.add(token)
                targets.append(token)
        return targets

    @staticmethod
    def _matches_scope(target: str, pattern: str) -> bool:
        """Whether ``target`` falls inside one scope/exclusion pattern.

        Supported patterns:
          * plain domain  — ``example.com`` matches itself and any subdomain
            (``api.example.com``) but not ``notexample.com``;
          * wildcard      — ``*.example.com`` matches only subdomains, and
            any other ``fnmatch`` pattern works as typed;
          * CIDR          — ``192.0.2.0/24`` matches IPs inside the network.
        Invalid/unparseable patterns match nothing (safe default).
        """
        pattern = (pattern or "").strip().lower()
        target = (target or "").strip().lower().rstrip(".")
        if not pattern or not target:
            return False

        if "/" in pattern:  # CIDR (or a URL — also treated as unmatchable)
            try:
                return ipaddress.ip_address(target) in ipaddress.ip_network(
                    pattern, strict=False
                )
            except ValueError:
                return False

        if "*" in pattern or "?" in pattern or "[" in pattern:
            return fnmatch(target, pattern)

        return target == pattern or target.endswith("." + pattern)

    @classmethod
    def _narrow_targets(cls, targets: list, scope: list, exclusions: list):
        """Apply scope/exclusions to the initial targets.

        Returns ``(kept, dropped)`` where ``dropped`` carries the reason so
        the wizard can show honest notices. An empty scope list means
        'everything is in scope' (only exclusions filter).
        """
        kept, dropped = [], []
        for target in targets:
            if any(cls._matches_scope(target, ex) for ex in exclusions):
                dropped.append((target, "excluded"))
            elif scope and not any(cls._matches_scope(target, sc) for sc in scope):
                dropped.append((target, "out of scope"))
            else:
                kept.append(target)
        return kept, dropped

    def _ask_targets(self) -> list:
        """Ask for targets until the whole batch is valid.

        Every token must be a bare domain, IP or CIDR. URL-like input gets
        a warning and an interactive fix (use the extracted host); anything
        invalid lists the reasons and re-asks the batch (retry).
        """
        while True:
            raw = Prompt.ask(
                "[bold cyan]◆ Target domain(s) or IP(s)[/bold cyan] "
                "[dim](comma/space separated)[/dim]"
            ).strip()
            targets = self._parse_targets(raw)
            if not targets:
                console.print("[yellow]⚠ At least one target is required.[/yellow]")
                continue

            pending, rejected = [], []
            from rich.markup import escape as _escape

            for token in targets:
                if self._looks_like_url(token):
                    host = self._host_from_url(token)
                    console.print(
                        f"[yellow]⚠ '{_escape(token)}' looks like a URL, "
                        "not a bare target.[/yellow]"
                    )
                    if host and Confirm.ask(
                        f"[cyan]  Use '{_escape(host)}' as the target instead?[/cyan]",
                        default=True,
                    ):
                        token = host
                    else:
                        rejected.append(
                            (token, "looks like a URL — enter the bare host")
                        )
                        continue
                pending.append(token)

            clean, bad = self._validate_targets(pending)
            rejected.extend(bad)
            if rejected:
                for token, reason in rejected:
                    console.print(
                        f"[red]✖ Invalid target '{_escape(str(token))}': {reason}[/red]"
                    )
                console.print(
                    "[dim]  Formats: domain (scanme.example.org), IPv4/IPv6, "
                    "CIDR (192.0.2.0/24). Try again.[/dim]"
                )
                continue
            if clean:
                # A URL swap can create duplicates ('a.com https://a.com'):
                # dedupe case-insensitively, keep first spelling.
                seen, unique = set(), []
                for token in clean:
                    key = token.lower().rstrip(".")
                    if key not in seen:
                        seen.add(key)
                        unique.append(token)
                return unique

    def _ask_scope_and_exclusions(self, targets: list):
        """Ask for scope limits and exclusions; narrow the targets for real."""
        console.print()
        scope_raw = Prompt.ask(
            "[bold cyan]◆ Scope limit[/bold cyan] "
            "[dim](domains/wildcards/CIDR allowed inside the targets, empty = all targets)[/dim]"
        ).strip()
        scope = self._parse_targets(scope_raw)

        exclusions_raw = Prompt.ask(
            "[bold cyan]◆ Exclusions[/bold cyan] "
            "[dim](domains/IPs to leave out, comma/space separated, empty = none)[/dim]"
        ).strip()
        exclusions = self._parse_targets(exclusions_raw)

        kept, dropped = self._narrow_targets(targets, scope, exclusions)
        for target, reason in dropped:
            console.print(f"  [yellow]− dropped '{target}' ({reason})[/yellow]")
        if dropped and not kept:
            console.print("[red]✖ Every target was dropped by your own scope/exclusions.[/red]")
            sys.exit(0)
        return kept, scope, exclusions

    def _confirm_authorization(self, targets: list) -> None:
        """Explicit authorization gate before launching any active module."""
        console.print()
        console.print("[bold white]◆ Authorization check[/bold white]")
        console.print(
            "  OSINT EYE performs passive and active reconnaissance. "
            "Run it only against systems you own or have permission to test."
        )
        from rich.markup import escape as _escape

        console.print(f"  Targets: {_escape(', '.join(targets))}")
        if not Confirm.ask(
            "[bold cyan]◆ I confirm I am authorized to test these targets[/bold cyan]",
            default=False,
        ):
            console.print("[red]✖ Authorization not confirmed — scan cancelled.[/red]")
            sys.exit(0)

    # ── main flow ────────────────────────────────────────────────────────
    def start(self) -> list:
        """Run the wizard and return argparse-ready arguments (no prog name)."""
        try:
            console.clear()
        except Exception:  # pragma: no cover - non-tty consoles
            pass
        self.cli.print_banner()
        console.print("[bold white]◆ Interactive Setup[/bold white]")
        console.print("[dim]Configure your reconnaissance scan — offline, no API keys.[/dim]")
        console.print()

        args_list: list = []

        # 1. Targets (positional — first element of the returned args)
        targets = self._ask_targets()

        # 2. Scope, exclusions and explicit authorization gate. The gate
        # runs BEFORE anything else so active modules never start unconfirmed.
        targets, scope, exclusions = self._ask_scope_and_exclusions(targets)
        self._confirm_authorization(targets)
        args_list.extend(targets)

        # 3. Depth
        depth = Prompt.ask(
            "[bold cyan]◆ Scan depth[/bold cyan]",
            choices=["quick", "normal", "deep", "full"],
            default="normal",
        )
        args_list.extend(["--depth", depth])

        # 4. AI + cache
        if not Confirm.ask("[bold cyan]◆ Use local AI analysis?[/bold cyan]", default=True):
            args_list.append("--no-ai")
        if not Confirm.ask("[bold cyan]◆ Use scan cache for faster re-runs?[/bold cyan]", default=True):
            args_list.append("--no-cache")

        # 5. Stealth + Rich output
        if Confirm.ask("[bold cyan]◆ Stealth mode (slow, low-noise scanning)?[/bold cyan]", default=False):
            args_list.append("--stealth")
        if Confirm.ask("[bold cyan]◆ Spectacular Rich output?[/bold cyan]", default=True):
            args_list.append("--rich")

        # 6. Output base name
        default_out = (
            "osint_eye_"
            + targets[0].replace("/", "_").replace(".", "_").replace(":", "_")
        )
        output = Prompt.ask(
            "[bold cyan]◆ Output base filename[/bold cyan]", default=default_out
        )
        if output and output != default_out:
            args_list.extend(["--output", output])

        # 7. Extras
        if Confirm.ask("[bold cyan]◆ Generate AI Red Team Playbook after scan?[/bold cyan]", default=False):
            args_list.append("--agent")
        if Confirm.ask("[bold cyan]◆ Executive PDF report?[/bold cyan]", default=False):
            args_list.append("--pdf")
        if Confirm.ask("[bold cyan]◆ Launch web dashboard after scan?[/bold cyan]", default=False):
            args_list.append("--dashboard")
        if Confirm.ask("[bold cyan]◆ Export graph to Neo4j Cypher?[/bold cyan]", default=False):
            cypher = Prompt.ask(
                "[bold cyan]  Cypher filename[/bold cyan]",
                default=f"osint_eye_{targets[0]}.cypher",
            )
            args_list.extend(["--export-cypher", cypher])

        console.print()
        summary = Text("  ")
        summary.append("✔ ", style="bold green")
        summary.append("Configuration ready — launching OSINT EYE", style="bold white")
        console.print(summary)
        # Targets come from user input: escape() keeps a value like
        # "x[/bold]y.com" from aborting the launch with Rich MarkupError.
        from rich.markup import escape as _escape

        console.print(f"  [dim]args: {_escape(' '.join(args_list))}[/dim]")
        console.print()
        return args_list


if __name__ == "__main__":  # pragma: no cover
    print(InteractiveWizard().start())
