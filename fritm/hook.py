#!/usr/bin/env python3

from pathlib import Path
import sys

import click
import frida

SCRIPT = (Path(__file__).parent / "script.js").read_text()


def hook(process, port=8080):
    if str.isdigit(process):
        process = int(process)
    session = frida.attach(process)
    script = SCRIPT.replace("8080", str(port))
    frida_script = session.create_script(SCRIPT)
    frida_script.load()


@click.command(help="Process: Unique name or PID of the process to attach to")
@click.argument("process")
@click.option(
    "-p",
    "--port",
    type=int,
    help="Local port to redirect to",
    default=8080,
    show_default=True,
)
def _main(process, port):
    hook(process, port)
    sys.stdin.read()  # infinite loop


if __name__ == "__main__":
    _main()
