"""OSINT EYE - Interactive Wizard"""

from rich.console import Console
from rich.prompt import Prompt, Confirm
import sys
import os

# Ensure import works dynamically 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ui.rich_cli import RichCLI

console = Console()

class InteractiveWizard:
    """CLI wizard to guide users through OSINT EYE setup interactively"""
    
    def __init__(self):
        self.cli = RichCLI()
        
    def start(self) -> list:
        console.clear()
        self.cli.print_banner()
        console.print("[dim]Interactive Setup Mode[/dim]\n")
        
        args_list = []
        
        target = Prompt.ask("[bold cyan]🎯 Enter the target domain/IP[/bold cyan]")
        args_list.append(target)
        
        depth = Prompt.ask(
            "[bold cyan]⚙️ Select scan depth[/bold cyan]", 
            choices=["quick", "normal", "deep", "full"], 
            default="normal"
        )
        args_list.extend(["--depth", depth])
        
        use_agent = Confirm.ask("[bold cyan]🤖 Run AI Agent Playbook after scan?[/bold cyan]", default=True)
        if use_agent:
            args_list.append("--agent")
            
        export_neo4j = Confirm.ask("[bold cyan]📊 Export graph map to Neo4j Cypher?[/bold cyan]", default=False)
        if export_neo4j:
            args_list.extend(["--export-cypher", f"osint_eye_{target}.cypher"])
            
        stealth = Confirm.ask("[bold cyan]🕵️  Run in Stealth Mode (slow rate limits, avoid noisy tools)?[/bold cyan]", default=False)
        if stealth:
            args_list.append("--stealth")
            
        console.print("\n[bold green]✓ Configuration ready. Executing OSINT EYE...[/bold green]\n")
        return args_list
