"""OSINT EYE - Interactive Wizard

Guided setup that runs fully offline and returns a list of CLI arguments
consumed by ``osint_eye.py``'s argparse parser. The first element is the
positional target (NOT the program name); every flag emitted here exists in
the parser: --depth, --stealth, --no-ai, --no-cache, --rich, --output,
--agent, --pdf, --dashboard, --export-cypher.
"""

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

    def _ask_targets(self) -> list:
        while True:
            raw = Prompt.ask(
                "[bold cyan]◆ Target domain(s) or IP(s)[/bold cyan] "
                "[dim](comma/space separated)[/dim]"
            ).strip()
            targets = self._parse_targets(raw)
            if targets:
                return targets
            console.print("[yellow]⚠ At least one target is required.[/yellow]")

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
        args_list.extend(targets)

        # 2. Depth
        depth = Prompt.ask(
            "[bold cyan]◆ Scan depth[/bold cyan]",
            choices=["quick", "normal", "deep", "full"],
            default="normal",
        )
        args_list.extend(["--depth", depth])

        # 3. AI + cache
        if not Confirm.ask("[bold cyan]◆ Use local AI analysis?[/bold cyan]", default=True):
            args_list.append("--no-ai")
        if not Confirm.ask("[bold cyan]◆ Use scan cache for faster re-runs?[/bold cyan]", default=True):
            args_list.append("--no-cache")

        # 4. Stealth + Rich output
        if Confirm.ask("[bold cyan]◆ Stealth mode (slow, low-noise scanning)?[/bold cyan]", default=False):
            args_list.append("--stealth")
        if Confirm.ask("[bold cyan]◆ Spectacular Rich output?[/bold cyan]", default=True):
            args_list.append("--rich")

        # 5. Output base name
        default_out = (
            "osint_eye_"
            + targets[0].replace("/", "_").replace(".", "_").replace(":", "_")
        )
        output = Prompt.ask(
            "[bold cyan]◆ Output base filename[/bold cyan]", default=default_out
        )
        if output and output != default_out:
            args_list.extend(["--output", output])

        # 6. Extras
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
