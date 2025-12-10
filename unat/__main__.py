#!/usr/bin/env python3
"""
UNAT - Universal Native Analysis Toolkit
Main CLI entry point
"""

import sys
import logging
import click
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: Rich library not available. Install with: pip install rich")

# Version
__version__ = "0.1.0"

# Setup console
console = Console() if RICH_AVAILABLE else None


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO

    if RICH_AVAILABLE:
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(console=console, rich_tracebacks=True)]
        )
    else:
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )


@click.group()
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose logging')
@click.option('--version', is_flag=True, help='Show version information')
@click.pass_context
def cli(ctx, verbose, version):
    """
    UNAT - Universal Native Analysis Toolkit

    Android APK reverse engineering and security analysis tool.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose

    setup_logging(verbose)

    if version:
        if RICH_AVAILABLE:
            console.print(f"[bold cyan]UNAT[/bold cyan] version [green]{__version__}[/green]")
        else:
            print(f"UNAT version {__version__}")
        ctx.exit()


@cli.command()
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('-o', '--output', help='Output directory for analysis results')
@click.option('--extract-libs', is_flag=True, help='Extract native libraries')
@click.pass_context
def analyze(ctx, apk_path, output, extract_libs):
    """
    Analyze an APK file

    Extracts comprehensive information from the APK including:
    - Package information
    - Permissions
    - Components (activities, services, receivers, providers)
    - Native libraries
    - DEX files
    """
    try:
        from unat.core.apk_handler import APKHandler

        if RICH_AVAILABLE:
            console.print(f"\n[bold]Analyzing APK:[/bold] {apk_path}\n")
        else:
            print(f"\nAnalyzing APK: {apk_path}\n")

        handler = APKHandler(apk_path)
        info = handler.extract_info()

        # Display summary
        if RICH_AVAILABLE:
            _display_apk_info_rich(info, handler)
        else:
            print(handler.get_summary())

        # Extract native libraries if requested
        if extract_libs:
            output_dir = output or "output/libs"
            if RICH_AVAILABLE:
                console.print(f"\n[yellow]Extracting native libraries to:[/yellow] {output_dir}")
            else:
                print(f"\nExtracting native libraries to: {output_dir}")

            extracted = handler.extract_all_native_libs(output_dir)

            if RICH_AVAILABLE:
                console.print(f"[green]Extracted {len(extracted)} libraries[/green]")
            else:
                print(f"Extracted {len(extracted)} libraries")

    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[bold red]Error:[/bold red] {e}")
        else:
            print(f"Error: {e}")
        sys.exit(1)


@cli.command()
@click.option('-s', '--serial', help='Specific device serial')
@click.option('--list', 'list_all', is_flag=True, help='List all connected devices')
@click.pass_context
def device(ctx, serial, list_all):
    """
    Manage Android device connections

    Connect to Android devices via ADB and check Frida availability.
    """
    try:
        from unat.core.device_manager import DeviceManager

        manager = DeviceManager()

        if list_all:
            devices = manager.list_devices()
            if RICH_AVAILABLE:
                if devices:
                    table = Table(title="Connected Devices")
                    table.add_column("Serial", style="cyan")
                    for dev in devices:
                        table.add_row(dev)
                    console.print(table)
                else:
                    console.print("[yellow]No devices found[/yellow]")
            else:
                if devices:
                    print("Connected Devices:")
                    for dev in devices:
                        print(f"  - {dev}")
                else:
                    print("No devices found")
            return

        # Connect to device
        if manager.connect(serial):
            if RICH_AVAILABLE:
                _display_device_info_rich(manager)
            else:
                print(manager.get_device_summary())
        else:
            if RICH_AVAILABLE:
                console.print("[bold red]Failed to connect to device[/bold red]")
            else:
                print("Failed to connect to device")
            sys.exit(1)

    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[bold red]Error:[/bold red] {e}")
        else:
            print(f"Error: {e}")
        sys.exit(1)


@cli.command()
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('-s', '--serial', help='Specific device serial')
@click.option('-r', '--reinstall', is_flag=True, help='Reinstall if already installed')
@click.pass_context
def install(ctx, apk_path, serial, reinstall):
    """
    Install an APK on a connected device
    """
    try:
        from unat.core.device_manager import DeviceManager

        manager = DeviceManager()

        if not manager.connect(serial):
            if RICH_AVAILABLE:
                console.print("[bold red]Failed to connect to device[/bold red]")
            else:
                print("Failed to connect to device")
            sys.exit(1)

        if RICH_AVAILABLE:
            console.print(f"\n[bold]Installing APK:[/bold] {apk_path}")
        else:
            print(f"\nInstalling APK: {apk_path}")

        if manager.install_apk(apk_path, reinstall=reinstall):
            if RICH_AVAILABLE:
                console.print("[bold green]Installation successful![/bold green]")
            else:
                print("Installation successful!")
        else:
            if RICH_AVAILABLE:
                console.print("[bold red]Installation failed[/bold red]")
            else:
                print("Installation failed")
            sys.exit(1)

    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[bold red]Error:[/bold red] {e}")
        else:
            print(f"Error: {e}")
        sys.exit(1)


@cli.command()
@click.argument('package_name')
@click.option('-s', '--serial', help='Specific device serial')
@click.option('--spawn', is_flag=True, help='Spawn the app instead of attaching')
@click.option('--package-only', is_flag=True, default=True, help='Only enumerate app package classes (default)')
@click.option('--filter-obfuscated', is_flag=True, help='Only show obfuscated classes')
@click.option('--no-methods', is_flag=True, help='Skip method enumeration (faster)')
@click.option('-o', '--output', help='Output file (JSON format)')
@click.option('--max-classes', type=int, help='Maximum number of classes to process')
@click.pass_context
def discover(ctx, package_name, serial, spawn, package_only, filter_obfuscated, no_methods, output, max_classes):
    """
    Discover Java classes and methods in a running application

    Uses Frida to dynamically enumerate loaded Java classes and their methods.
    Useful for understanding app structure and finding obfuscated code.

    Example:
        unat discover com.example.app
        unat discover com.example.app --filter-obfuscated
        unat discover com.example.app --spawn --no-methods
    """
    try:
        from unat.core.device_manager import DeviceManager
        from unat.discovery.java_discovery import discover_java_classes

        if RICH_AVAILABLE:
            console.print(f"\n[bold]Java Discovery:[/bold] {package_name}\n")
        else:
            print(f"\nJava Discovery: {package_name}\n")

        # Connect to device
        manager = DeviceManager()
        if not manager.connect(serial):
            if RICH_AVAILABLE:
                console.print("[bold red]Failed to connect to device[/bold red]")
            else:
                print("Failed to connect to device")
            sys.exit(1)

        # Get Frida device
        frida_device = manager.get_frida_device()
        if not frida_device:
            if RICH_AVAILABLE:
                console.print("[bold red]Frida not available on device[/bold red]")
            else:
                print("Frida not available on device")
            sys.exit(1)

        # Perform discovery
        if RICH_AVAILABLE:
            console.print("[yellow]Starting discovery...[/yellow]")
        else:
            print("Starting discovery...")

        result = discover_java_classes(
            frida_device=frida_device,
            package_name=package_name,
            spawn=spawn,
            package_only=package_only,
            obfuscated_only=filter_obfuscated,
            enumerate_methods=not no_methods
        )

        if not result:
            if RICH_AVAILABLE:
                console.print("[bold red]Discovery failed[/bold red]")
            else:
                print("Discovery failed")
            sys.exit(1)

        # Display results
        if RICH_AVAILABLE:
            _display_discovery_results_rich(result, max_classes)
        else:
            _display_discovery_results_plain(result, max_classes)

        # Save to file if requested
        if output:
            import json
            output_data = {
                'package_name': result.package_name,
                'total_classes': result.total_classes,
                'total_methods': result.total_methods,
                'obfuscated_classes': result.obfuscated_classes,
                'classes': [
                    {
                        'name': c.name,
                        'package': c.package,
                        'is_obfuscated': c.is_obfuscated,
                        'methods': c.methods[:10] if c.methods else []  # Limit methods in JSON
                    }
                    for c in (result.classes[:max_classes] if max_classes else result.classes)
                ]
            }

            with open(output, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)

            if RICH_AVAILABLE:
                console.print(f"\n[green]Results saved to:[/green] {output}")
            else:
                print(f"\nResults saved to: {output}")

    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[bold red]Error:[/bold red] {e}")
        else:
            print(f"Error: {e}")
        import traceback
        if ctx.obj.get('verbose'):
            traceback.print_exc()
        sys.exit(1)


def _display_discovery_results_rich(result, max_classes=None):
    """Display discovery results using Rich formatting"""
    # Summary panel
    summary = f"""[cyan]Package:[/cyan] {result.package_name}
[cyan]Total Classes:[/cyan] {result.total_classes}
[cyan]Total Methods:[/cyan] {result.total_methods}
[cyan]Obfuscated Classes:[/cyan] {result.obfuscated_classes} ({result.obfuscated_classes / max(result.total_classes, 1) * 100:.1f}%)"""

    console.print(Panel(summary, title="[bold]Discovery Summary[/bold]", border_style="green"))

    # Classes table
    classes_to_show = result.classes[:max_classes] if max_classes else result.classes[:50]

    if classes_to_show:
        table = Table(title=f"Java Classes (showing {len(classes_to_show)} of {result.total_classes})")
        table.add_column("Class Name", style="cyan", no_wrap=False)
        table.add_column("Methods", style="magenta", justify="right")
        table.add_column("Obfuscated", style="yellow", justify="center")

        for class_info in classes_to_show:
            obf_marker = "✓" if class_info.is_obfuscated else ""
            method_count = len(class_info.methods) if class_info.methods else 0

            # Color code class name
            class_name = class_info.name
            if class_info.is_obfuscated:
                class_name = f"[red]{class_name}[/red]"

            table.add_row(
                class_name,
                str(method_count),
                obf_marker
            )

        console.print("\n")
        console.print(table)

        # Show some method examples
        if classes_to_show and classes_to_show[0].methods:
            console.print(f"\n[bold cyan]Example Methods from {classes_to_show[0].name}:[/bold cyan]")
            for method in classes_to_show[0].methods[:5]:
                console.print(f"  • {method}")


def _display_discovery_results_plain(result, max_classes=None):
    """Display discovery results in plain text"""
    print("\n=== Discovery Summary ===")
    print(f"Package: {result.package_name}")
    print(f"Total Classes: {result.total_classes}")
    print(f"Total Methods: {result.total_methods}")
    print(f"Obfuscated Classes: {result.obfuscated_classes}")

    classes_to_show = result.classes[:max_classes] if max_classes else result.classes[:50]

    print(f"\n=== Classes (showing {len(classes_to_show)} of {result.total_classes}) ===")
    for class_info in classes_to_show:
        obf_marker = " [OBFUSCATED]" if class_info.is_obfuscated else ""
        method_count = len(class_info.methods) if class_info.methods else 0
        print(f"{class_info.name} ({method_count} methods){obf_marker}")


def _display_apk_info_rich(info, handler):
    """Display APK information using Rich formatting"""
    # Basic info panel
    basic_info = f"""[cyan]Package:[/cyan] {info.package_name}
[cyan]App Name:[/cyan] {info.app_name}
[cyan]Version:[/cyan] {info.version_name} ({info.version_code})
[cyan]File Size:[/cyan] {info.file_size / 1024 / 1024:.2f} MB"""

    console.print(Panel(basic_info, title="[bold]Application Information[/bold]", border_style="blue"))

    # SDK Info
    sdk_info = f"""[cyan]Min SDK:[/cyan] {info.min_sdk}
[cyan]Target SDK:[/cyan] {info.target_sdk}"""

    console.print(Panel(sdk_info, title="[bold]SDK Versions[/bold]", border_style="green"))

    # Security
    debuggable_color = "red" if info.is_debuggable else "green"
    security_info = f"""[cyan]Debuggable:[/cyan] [{debuggable_color}]{info.is_debuggable}[/{debuggable_color}]"""

    console.print(Panel(security_info, title="[bold]Security[/bold]", border_style="yellow"))

    # Components table
    components_table = Table(title="Components")
    components_table.add_column("Type", style="cyan")
    components_table.add_column("Count", style="magenta")

    components_table.add_row("Activities", str(len(info.activities)))
    components_table.add_row("Services", str(len(info.services)))
    components_table.add_row("Receivers", str(len(info.receivers)))
    components_table.add_row("Providers", str(len(info.providers)))

    console.print(components_table)

    # Permissions
    if info.permissions:
        console.print(f"\n[bold cyan]Permissions ({len(info.permissions)}):[/bold cyan]")
        for perm in info.permissions[:10]:  # Show first 10
            console.print(f"  • {perm}")
        if len(info.permissions) > 10:
            console.print(f"  ... and {len(info.permissions) - 10} more")

    # Native libraries
    if info.native_libraries:
        libs_by_arch = handler.get_native_libraries_by_arch()
        console.print(f"\n[bold cyan]Native Libraries ({len(info.native_libraries)}):[/bold cyan]")
        for arch, libs in libs_by_arch.items():
            console.print(f"  [yellow]{arch}:[/yellow]")
            for lib in libs[:5]:  # Show first 5 per arch
                console.print(f"    • {lib}")
            if len(libs) > 5:
                console.print(f"    ... and {len(libs) - 5} more")


def _display_device_info_rich(manager):
    """Display device information using Rich formatting"""
    info = manager.device_info
    if not info:
        console.print("[red]No device information available[/red]")
        return

    device_info = f"""[cyan]Serial:[/cyan] {info.serial}
[cyan]Model:[/cyan] {info.model}
[cyan]Android:[/cyan] {info.android_version} (SDK {info.sdk_version})
[cyan]Architecture:[/cyan] {info.architecture}"""

    console.print(Panel(device_info, title="[bold]Device Information[/bold]", border_style="blue"))

    # Status indicators
    status_table = Table(title="Status")
    status_table.add_column("Feature", style="cyan")
    status_table.add_column("Status", style="magenta")

    status_table.add_row("Emulator", "✓" if info.is_emulator else "✗")
    status_table.add_row("Rooted", "✓" if info.is_rooted else "✗")
    status_table.add_row("Frida Available", "✓" if info.frida_available else "✗")

    console.print(status_table)


def main():
    """Main entry point"""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console.print("\n[yellow]Interrupted by user[/yellow]")
        else:
            print("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        else:
            print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
