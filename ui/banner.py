from rich.console import Console
from rich.panel import Panel

console = Console()

def show_banner():
    raw_lines = [
        "                                                                     ",
        "                                                                     ",
        "    █████           █████     █████████                      █████   ",
        "   ▒▒███           ▒▒███     ███▒▒▒▒▒███                    ▒▒███    ",
        "  ███████   ██████  ███████  ▒███    ▒▒▒  ████████   ██████  ███████  ",
        " ███▒▒███  ███▒▒███▒▒▒███▒   ▒▒█████████ ▒▒███▒▒███ ███▒▒███▒▒▒███▒   ",
        "▒███ ▒███ ▒███ ▒███  ▒███     ▒▒▒▒▒▒▒▒███ ▒███ ▒███▒███ ▒███  ▒███    ",
        "▒███ ▒███ ▒███ ▒███  ▒███ ███ ███    ▒███ ▒███ ▒███▒███ ▒███  ▒███ ███",
        "▒▒████████▒▒██████   ▒▒█████ ▒▒█████████  ▒███████ ▒▒██████   ▒▒█████ ",
        " ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒     ▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒   ▒███▒▒▒   ▒▒▒▒▒▒     ▒▒▒▒▒  ",
        "                                          ▒███                        ",
        "                                          █████                       ",
        "                                         ▒▒▒▒▒                        ",
    ]

    inner_width = 96
    centered_lines = [line.center(inner_width) for line in raw_lines]
    art = "\n".join(centered_lines)

    subtitle = "by SagnikMukherjee"
    banner_text = art + "\n\n" + subtitle.center(inner_width)

    panel = Panel(
        banner_text,
        border_style="spring_green1",
        title="v 0.0.1",
        width=100,
        title_align="center",
        style="grey89"
    )

    console.print(panel)
