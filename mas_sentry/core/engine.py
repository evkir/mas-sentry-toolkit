# SPDX-License-Identifier: AGPL-3.0-or-later
from rich.console import Console
from rich.panel import Panel
from .config import SentryConfig
from .session import ScanSession

console = Console()

class SentryEngine:
    VERSION = "1.0.0"
    BANNER = """
    ███╗   ███╗ █████╗ ███████╗    ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
    ████╗ ████║██╔══██╗██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
    ██╔████╔██║███████║███████╗    ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝
    ██║╚██╔╝██║██╔══██║╚════██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝
    ██║ ╚═╝ ██║██║  ██║███████║    ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝
    """

    def __init__(self, config: SentryConfig = None):
        self.config = config or SentryConfig()
        self.session = None

    def start_session(self, target: str, protocol: str) -> ScanSession:
        self.session = ScanSession(target=target, protocol=protocol)
        console.print(Panel(self.BANNER, style="bold red"))
        console.print(f"[bold green]Session {self.session.session_id} started[/bold green]")
        return self.session

    def end_session(self):
        if self.session:
            summary = self.session.summary()
            console.print(Panel(str(summary), title="Session Summary", style="bold blue"))
