import argparse
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Mapping
from urllib.parse import parse_qsl, urlparse

try:
    import dns.resolver
except ImportError:
    dns = None

SUS_CMDI = {
	"execute",
	"dir",
	"daemon",
	"cli",
	"log",
	"cmd",
	"download",
	"ip",
	"upload",
	"message",
	"input_file",
	"format",
	"expression",
	"data",
	"bsh",
	"bash",
	"shell",
	"command",
	"range",
	"sort",
	"host",
	"exec",
	"code",
}

SUS_DEBUG = {
	"test",
	"reset",
	"config",
	"shell",
	"admin",
	"exec",
	"load",
	"cfg",
	"dbg",
	"edit",
	"root",
	"create",
	"access",
	"disable",
	"alter",
	"make",
	"grant",
	"adm",
	"toggle",
	"execute",
	"clone",
	"delete",
	"enable",
	"rename",
	"debug",
	"modify",
	"stacktrace",
}

SUS_FILEINC = {
	"root",
	"directory",
	"path",
	"style",
	"folder",
	"default-language",
	"url",
	"platform",
	"textdomain",
	"document",
	"template",
	"pg",
	"php_path",
	"doc",
	"type",
	"lang",
	"token",
	"name",
	"pdf",
	"file",
	"etc",
	"api",
	"app",
	"resource-type",
	"controller",
	"filename",
	"page",
	"f",
	"view",
	"input_file",
}

SUS_IDOR = {
	"count",
	"key",
	"user",
	"id",
	"extended_data",
	"uid2",
	"group",
	"team_id",
	"data-id",
	"no",
	"username",
	"email",
	"account",
	"doc",
	"uuid",
	"profile",
	"number",
	"user_id",
	"edit",
	"report",
	"order",
}

SUS_OPENREDIRECT = {
	"u",
	"redirect_uri",
	"failed",
	"r",
	"referer",
	"return_url",
	"redirect_url",
	"prejoin_data",
	"continue",
	"redir",
	"return_to",
	"origin",
	"redirect_to",
	"next",
	"callback_uri",
	"callback_url",
	"continue_to_url",
	"continue_url",
	"destination_url",
	"final_url",
	"goto",
	"href",
	"link",
	"next_location",
	"next_page",
	"next_url",
	"page_url",
	"post_login_redirect",
	"redirect_target",
	"resource",
	"return_destination",
	"return_path",
	"service_url",
	"target_url",
    "target",
}

SUS_SQLI = {
	"process",
	"string",
	"id",
	"referer",
	"password",
	"pwd",
	"field",
	"view",
	"sleep",
	"column",
	"log",
	"token",
	"sel",
	"select",
	"sort",
	"from",
	"search",
	"update",
	"pub_group_id",
	"row",
	"results",
	"role",
	"table",
	"multi_layer_map_list",
	"order",
	"filter",
	"params",
	"user",
	"fetch",
	"limit",
	"keyword",
	"email",
	"query",
	"c",
	"name",
	"where",
	"number",
	"phone_number",
	"delete",
	"report",
	"q",
	"sql",
}

SUS_SSRF = {
	"sector_identifier_uri",
	"request_uris",
	"logo_uri",
	"jwks_uri",
	"start",
	"path",
	"domain",
	"source",
	"url",
	"site",
	"view",
	"template",
	"page",
	"show",
	"val",
	"dest",
	"metadata",
	"out",
	"feed",
	"navigation",
	"image_host",
	"uri",
	"next",
	"continue",
	"host",
	"window",
	"dir",
	"reference",
	"filename",
	"html",
	"to",
	"return",
	"open",
	"port",
	"stop",
	"validate",
	"resturl",
	"callback",
	"name",
	"data",
	"ip",
	"redirect",
	"target",
	"referer",
}

SUS_SSTI = {
	"preview",
	"activity",
	"id",
	"name",
	"content",
	"view",
	"template",
	"redirect",
}

SUS_XSS = {
	"path",
	"admin",
	"class",
	"atb",
	"redirect_uri",
	"other",
	"utm_source",
	"currency",
	"dir",
	"title",
	"endpoint",
	"return_url",
	"users",
	"cookie",
	"state",
	"callback",
	"militarybranch",
	"e",
	"referer",
	"password",
	"author",
	"body",
	"status",
	"utm_campaign",
	"value",
	"text",
	"search",
	"flaw",
	"vote",
	"pathname",
	"params",
	"user",
	"t",
	"utm_medium",
	"q",
	"email",
	"what",
	"file",
	"data-original",
	"description",
	"subject",
	"action",
	"u",
	"nickname",
	"color",
	"language_id",
	"auth",
	"samlresponse",
	"return",
	"readyfunction",
	"where",
	"tags",
	"cvo_sid1",
	"target",
	"format",
	"back",
	"term",
	"r",
	"id",
	"url",
	"view",
	"username",
	"sequel",
	"type",
	"city",
	"src",
	"p",
	"label",
	"ctx",
	"style",
	"html",
	"ad_type",
	"s",
	"issues",
	"query",
	"c",
	"shop",
	"redirect",
	"page",
	"prefv1",
	"destination",
	"mode",
	"data",
	"error",
	"editor",
	"wysiwyg",
	"widget",
	"msg",
}

SUS_MASSASSIGNMENT = {
	"user",
	"profile",
	"role",
	"settings",
	"data",
	"attributes",
	"post",
	"comment",
	"order",
	"product",
	"form_fields",
	"request",
}


SUS_PARAMETER_CATEGORIES: Mapping[str, set[str]] = {
	"cmdi": SUS_CMDI,
	"debug": SUS_DEBUG,
	"fileinc": SUS_FILEINC,
	"idor": SUS_IDOR,
	"openredirect": SUS_OPENREDIRECT,
	"sqli": SUS_SQLI,
	"ssrf": SUS_SSRF,
	"ssti": SUS_SSTI,
	"xss": SUS_XSS,
	"massassignment": SUS_MASSASSIGNMENT,
}


def parse_arguments() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		prog="sus_scanner",
		description="Scan URLs for suspicious query parameters grouped by category."
	)
	parser.add_argument(
		"-i",
		"--input",
		required=True,
		help="Path to the input file containing one URL per line.",
	)
	parser.add_argument(
		"-o",
		"--output",
		required=True,
		help="Directory where categorized output files should be written.",
	)
	return parser.parse_args()



def read_urls(path: Path) -> Iterable[str]:
	with path.open(encoding="utf-8", errors="replace") as fh:
		for line in fh:
			clean = line.strip()
			if not clean or clean.startswith("#"):
				continue
			yield clean



def normalize_host(hostname: str) -> str:
	return hostname.lower()


def sanitize_host_for_filename(hostname: str) -> str:
	"""Make the hostname safe to use in filenames."""
	return hostname.replace(":", "-")


def _resolve_host_dnspython(host: str, timeout: float) -> bool:
	"""Resolve the host with dnspython using a per-query timeout and enough lifetime for each nameserver."""
	resolver = dns.resolver.Resolver()
	nameserver_count = max(1, len(resolver.nameservers))
	# Allow one timeout slice per nameserver to avoid failing before a working server is tried.
	resolver.timeout = timeout
	resolver.lifetime = timeout * nameserver_count
	try:
		# Try A record
		answer = resolver.resolve(host, "A", raise_on_no_answer=False)
		if answer.rrset is not None:
			return True

		# Try AAAA record
		answer = resolver.resolve(host, "AAAA", raise_on_no_answer=False)
		if answer.rrset is not None:
			return True

		return False
	except (
		dns.resolver.NXDOMAIN,
		dns.resolver.Timeout,
		dns.resolver.NoAnswer,
		dns.resolver.NoNameservers,
	):
		return False


def _resolve_host_stdlib(host: str) -> bool:
    """Fallback to stdlib getaddrinfo (no hard timeout control)."""
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def populate_dns_cache(
	hosts: Iterable[str],
	cache: dict[str, bool],
	lock: threading.Lock,
	timeout: float = 5.0,
) -> None:
	host_list = list(hosts)
	total = len(host_list)
	if total == 0:
		return 0, 0

	workers = min(128, total)  # you can tune this
	use_dnspython = dns is not None

	def worker(host: str) -> tuple[str, bool]:
		if use_dnspython:
			resolved = _resolve_host_dnspython(host, timeout=timeout)
		else:
			# Last resort – no real fail-fast here
			resolved = _resolve_host_stdlib(host)
			print(f"[DEBUG] {host} -> {resolved}")
		return host, resolved

	processed = 0
	with ThreadPoolExecutor(max_workers=workers) as executor:
		futures = {executor.submit(worker, h): h for h in host_list}
		for future in as_completed(futures):
			host, resolved = future.result()
			with lock:
				cache[host] = resolved
				processed += 1
				percent = processed / total * 100
			print(
				f"DNS progress: {processed}/{total} hosts resolved ({percent:.1f}%)",
				end="\r",
				flush=True,
			)
	print()


def categorize_url(url: str, dns_cache: dict[str, bool], dns_lock: threading.Lock) -> tuple[str, list[tuple[str, str, list[str]]]]:
	parsed = urlparse(url)
	if not parsed.hostname:
		return "", []
	normal_host = normalize_host(parsed.hostname)
	with dns_lock:
		resolved = dns_cache.get(normal_host)
	if not resolved:
		return normal_host, []
	param_names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
	if not param_names:
		return normal_host, []
	path = parsed.path or "/"
	matches: list[tuple[str, str, list[str]]] = []
	for category, tokens in SUS_PARAMETER_CATEGORIES.items():
		matched = sorted(tokens & param_names)
		if matched:
			matches.append((category, path, matched))
	return normal_host, matches


def write_results(
	results: Mapping[str, Mapping[str, Mapping[str, Mapping[str, list[str]]]]],
	output_dir: Path,
) -> None:
	table_header = [
		"| Path | Parameter | Examples |",
		"| --- | --- | --- |",
	]
	for host, categories in sorted(results.items()):
		if not host or not categories:
			continue
		safe_host = sanitize_host_for_filename(host)
		for category, paths in sorted(categories.items()):
			if not paths:
				continue
			rows = table_header.copy()
			for path, params in sorted(paths.items()):
				for param, examples in sorted(params.items()):
					if not examples:
						continue
					example_text = "<br>".join(examples)
					rows.append(f"| {path} | {param} | {example_text} |")
			if len(rows) == len(table_header):
				continue
			file_path = output_dir / f"{safe_host}-sus-{category}-urls.md"
			title_line = f"# {category.replace('-', ' ').title()} Suspicious Parameters - for {host}"
			with file_path.open("w", encoding="utf-8") as fh:
				fh.write(title_line + "\n\n" + "\n".join(rows) + "\n")


def main() -> int:
	args = parse_arguments()
	input_path = Path(args.input)
	output_dir = Path(args.output)
	if not input_path.exists():
		print(f"Input file {input_path} does not exist.")
		return 1
	urls = list(read_urls(input_path))
	if not urls:
		print("No URLs to scan.")
		return 0
	hosts: set[str] = set()
	for url in urls:
		parsed = urlparse(url)
		if not parsed.hostname:
			continue
		hosts.add(normalize_host(parsed.hostname))
	output_dir.mkdir(parents=True, exist_ok=True)
	per_host_results: dict[str, dict[str, dict[str, dict[str, list[str]]]]] = {}
	dns_cache: dict[str, bool] = {}
	dns_lock = threading.Lock()
	populate_dns_cache(hosts, dns_cache, dns_lock)
	total_hosts = len(hosts)
	successful_hosts = sum(1 for resolved in dns_cache.values() if resolved)
	print(f"{successful_hosts} out of {total_hosts} Hosts resolved successfully")
	progress_lock = threading.Lock()
	processed = 0
	total = len(urls)
	workers = min(32, (os.cpu_count() or 1) * 2)
	with ThreadPoolExecutor(max_workers=workers) as executor:
		future_to_url = {
			executor.submit(categorize_url, url, dns_cache, dns_lock): url
			for url in urls
		}
		for future in as_completed(future_to_url):
			url = future_to_url[future]
			host, matches = future.result()
			if host and matches:
				host_bucket = per_host_results.setdefault(host, {})
				for category, path, params in matches:
					category_bucket = host_bucket.setdefault(category, {})
					path_bucket = category_bucket.setdefault(path, {})
					for param in params:
						examples = path_bucket.setdefault(param, [])
						if url not in examples and len(examples) < 2:
							examples.append(url)
			with progress_lock:
				processed += 1
				percent = processed / total * 100
			print(
				f"Progress: {processed}/{total} URLs scanned ({percent:.1f}%)",
				end="\r",
				flush=True,
			)
	print()
	if not per_host_results:
		print("No suspicious URLs detected.")
		return 0
	write_results(per_host_results, output_dir)
	file_count = sum(len(categories) for categories in per_host_results.values())
	print(f"Wrote results for {file_count} host+category pairs to {output_dir}.")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())


