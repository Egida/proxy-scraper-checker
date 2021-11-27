#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ipaddress import IPv4Address
from os import mkdir
from random import shuffle
from shutil import rmtree
from threading import Thread
from time import sleep
from typing import Any, Dict, Iterable, Optional, Tuple

from maxminddb import open_database
from maxminddb.reader import Reader
from requests import get
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

import config


class ProxyScraperChecker:
    def __init__(
        self,
        *,
        timeout: float = 5,
        geolite2_city_mmdb: Optional[str] = None,
        ip_service: str = "https://checkip.amazonaws.com",
        http_sources: Optional[Iterable[str]] = None,
        socks4_sources: Optional[Iterable[str]] = None,
        socks5_sources: Optional[Iterable[str]] = None,
        console: Optional[Console] = None,
    ) -> None:
        """Scrape and check proxies from sources and save them to files.

        Args:
            geolite2_city_mmdb (str): Path to the GeoLite2-City.mmdb if you
                want to add location info for each proxy.
            ip_service (str): Service for getting your IP address and checking
                if proxies are valid.
            timeout (float): How many seconds to wait for the connection.
        """
        self.IP_SERVICE = ip_service.strip()
        self.TIMEOUT = timeout
        self.MMDB = geolite2_city_mmdb
        self.SOURCES = {
            proto: (sources,)
            if isinstance(sources, str)
            else tuple(set(sources))
            for proto, sources in (
                ("http", http_sources),
                ("socks4", socks4_sources),
                ("socks5", socks5_sources),
            )
            if sources
        }
        self.proxies: Dict[str, Dict[str, Optional[str]]] = {
            proto: {} for proto in self.SOURCES
        }
        self.proxies_count = {proto: 0 for proto in self.SOURCES}
        self.c = console or Console()

    @staticmethod
    def append_to_file(file_path: str, content: str) -> None:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"{content}\n")

    @staticmethod
    def get_geolocation(ip: Optional[str], reader: Reader) -> str:
        """Get proxy's geolocation.

        Args:
            ip (str): Proxy's ip.
            reader (Reader): mmdb Reader instance.

        Returns:
            str: ::Country Name::Region::City
        """
        if not ip:
            return "::None::None::None"
        geolocation = reader.get(ip)
        if not isinstance(geolocation, dict):
            return "::None::None::None"
        country = geolocation.get("country")
        if country:
            country = country["names"]["en"]
        else:
            country = geolocation.get("continent")
            if country:
                country = country["names"]["en"]
        region = geolocation.get("subdivisions")
        if region:
            region = region[0]["names"]["en"]
        city = geolocation.get("city")
        if city:
            city = city["names"]["en"]
        return f"::{country}::{region}::{city}"

    def run_threads(self, threads: Iterable[Thread]) -> None:
        """Start and join threads."""
        for t in threads:
            try:
                t.start()
            except RuntimeError:
                sleep(self.TIMEOUT)
                t.start()
        for t in threads:
            t.join()

    def fetch_source(
        self, source: str, proto: str, progress: Progress, task: TaskID
    ) -> None:
        """Get proxies from source.

        Args:
            source (str): Proxy list URL.
            proto (str): http/socks4/socks5.
        """
        try:
            with get(source.strip(), timeout=15) as r:
                status_code = r.status_code
                text = r.text
        except Exception as e:
            self.c.print(f"{source}: {e}")
        else:
            if status_code == 200:
                for proxy in text.splitlines():
                    proxy = (
                        proxy.replace(f"{proto}://", "")
                        .replace("https://", "")
                        .strip()
                    )
                    try:
                        IPv4Address(proxy.split(":")[0])
                    except Exception:
                        continue
                    self.proxies[proto][proxy] = None
            else:
                self.c.print(f"{source} status code: {status_code}")
        progress.update(task, advance=1, refresh=True)

    def check_proxy(
        self, proxy: str, proto: str, progress: Progress, task: TaskID
    ) -> None:
        """Check proxy validity.

        Args:
            proxy (str): ip:port.
            proto (str): http/socks4/socks5.
        """
        try:
            with get(
                self.IP_SERVICE,
                proxies={
                    "http": f"{proto}://{proxy}",
                    "https": f"{proto}://{proxy}",
                },
                timeout=self.TIMEOUT,
            ) as r:
                exit_node = r.text.strip()
            IPv4Address(exit_node)
        except Exception:
            self.proxies[proto].pop(proxy)
        else:
            self.proxies[proto][proxy] = exit_node
        progress.update(task, advance=1, refresh=True)

    def fetch_all_sources(self) -> None:
        """Get proxies from sources."""
        with self._get_progress() as progress:
            tasks = {
                proto: progress.add_task(
                    "[yellow]Scraper[/yellow] [red]::[/red]"
                    + f" [green]{proto.upper()}[/green]",
                    total=len(sources),
                )
                for proto, sources in self.SOURCES.items()
            }
            threads = [
                Thread(
                    target=self.fetch_source,
                    args=(source, proto, progress, tasks[proto]),
                    daemon=True,
                )
                for proto, sources in self.SOURCES.items()
                for source in sources
            ]
            self.run_threads(threads)
        for proto, proxies in self.proxies.items():
            self.proxies_count[proto] = len(proxies)

    def check_all_proxies(self) -> None:
        with self._get_progress() as progress:
            tasks = {
                proto: progress.add_task(
                    "[yellow]Checker[/yellow] [red]::[/red]"
                    + f" [green]{proto.upper()}[/green]",
                    total=len(proxies),
                )
                for proto, proxies in self.proxies.items()
            }
            threads = [
                Thread(
                    target=self.check_proxy,
                    args=(proxy, proto, progress, tasks[proto]),
                    daemon=True,
                )
                for proto, proxies in self.proxies.items()
                for proxy in proxies
            ]
            shuffle(threads)
            self.run_threads(threads)

    def sort_proxies(self) -> None:
        self.proxies = {
            proto: dict(sorted(proxies.items(), key=self._get_sorting_key))
            for proto, proxies in self.proxies.items()
        }

    def save_proxies(self) -> None:
        """Delete old proxies and save new ones."""
        dirs_to_delete = (
            "proxies",
            "proxies_anonymous",
            "proxies_geolocation",
            "proxies_geolocation_anonymous",
        )
        for dir in dirs_to_delete:
            try:
                rmtree(dir)
            except FileNotFoundError:
                pass
        dirs_to_create = (
            dirs_to_delete if self.MMDB else ("proxies", "proxies_anonymous")
        )
        for dir in dirs_to_create:
            mkdir(dir)

        # proxies and proxies_anonymous folders
        for proto, proxies in self.proxies.items():
            path = f"proxies/{proto}.txt"
            path_anonymous = f"proxies_anonymous/{proto}.txt"
            for proxy, exit_node in proxies.items():
                self.append_to_file(path, proxy)
                if exit_node != proxy.split(":")[0]:
                    self.append_to_file(path_anonymous, proxy)

        # proxies_geolocation and proxies_geolocation_anonymous folders
        if self.MMDB:
            with open_database(self.MMDB) as reader:
                for proto, proxies in self.proxies.items():
                    path = f"proxies_geolocation/{proto}.txt"
                    path_anonymous = (
                        f"proxies_geolocation_anonymous/{proto}.txt"
                    )
                    for proxy, exit_node in proxies.items():
                        line = proxy + self.get_geolocation(exit_node, reader)
                        self.append_to_file(path, line)
                        if exit_node != proxy.split(":")[0]:
                            self.append_to_file(path_anonymous, line)

    def main(self) -> None:
        self.fetch_all_sources()
        self.check_all_proxies()

        table = Table()
        table.add_column("Protocol", style="cyan")
        table.add_column("Working", style="magenta")
        table.add_column("Total", style="green")
        for proto, proxies in self.proxies.items():
            working = len(proxies)
            total = self.proxies_count[proto]
            percentage = working / total * 100
            table.add_row(
                proto.upper(), f"{working} ({percentage:.1f}%)", str(total)
            )
        self.c.print(table)

        self.sort_proxies()
        self.save_proxies()

        self.c.print(
            "[green]Proxy folders have been created in the current directory."
            + "\nThank you for using proxy-scraper-checker :)[/green]"
        )

    @staticmethod
    def _get_sorting_key(x: Tuple[str, Any]) -> Tuple[int, ...]:
        octets = x[0].replace(":", ".").split(".")
        return tuple(map(int, octets))

    def _get_progress(self) -> Progress:
        return Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:3.0f}%"),
            TextColumn("[blue][{task.completed}/{task.total}][/blue]"),
            TimeRemainingColumn(),
            console=self.c,
            auto_refresh=False,
        )


def main() -> None:
    ProxyScraperChecker(
        timeout=config.TIMEOUT,
        geolite2_city_mmdb="GeoLite2-City.mmdb"
        if config.GEOLOCATION
        else None,
        ip_service=config.IP_SERVICE,
        http_sources=config.HTTP_SOURCES if config.HTTP else None,
        socks4_sources=config.SOCKS4_SOURCES if config.SOCKS4 else None,
        socks5_sources=config.SOCKS5_SOURCES if config.SOCKS5 else None,
    ).main()


if __name__ == "__main__":
    main()
