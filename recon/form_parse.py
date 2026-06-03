import re
import shlex
from html.parser import HTMLParser
from urllib.parse import urljoin


class _UploadFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._form = None
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        ad = dict(attrs)
        if tag == "form":
            self._form = {
                "action": ad.get("action", ""),
                "method": (ad.get("method") or "GET").upper(),
                "enctype": ad.get("enctype", ""),
                "file_input": None,
                "submit": None,
                "hidden": [],
            }
            self._in_form = True
            return

        if not self._in_form or tag != "input":
            return

        typ = (ad.get("type") or "text").lower()
        name = ad.get("name")
        if not name:
            return

        if typ == "file":
            self._form["file_input"] = name
        elif typ == "submit":
            self._form["submit"] = (name, ad.get("value") or "")
        elif typ == "hidden":
            self._form["hidden"].append((name, ad.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
            self._in_form = False


def _pick_upload_form(forms):
    for f in forms:
        if f.get("file_input") and "multipart" in (f.get("enctype") or "").lower():
            return f
    for f in forms:
        if f.get("file_input"):
            return f
    return None


def url_from_command(command: str) -> str:
    m = re.search(r"https?://[^\s'\"<>]+", command or "")
    return m.group(0) if m else ""


def resolve_form_url(base_url: str, action: str) -> str:
    if not base_url:
        return action or ""
    if not action or action == "#":
        return base_url
    return urljoin(base_url, action)


def parse_upload_form_html(stdout: str, command: str = ""):
    """Parse first multipart/file upload form from HTML. Returns dict or None."""
    parser = _UploadFormParser()
    try:
        parser.feed(stdout or "")
        parser.close()
    except Exception:
        pass

    form = _pick_upload_form(parser.forms)
    if not form or not form.get("file_input"):
        return None

    base = url_from_command(command)
    url = resolve_form_url(base, form.get("action") or "")

    extra = []
    for name, value in form.get("hidden") or []:
        extra.append(f"{name}={value}")
    if form.get("submit"):
        name, value = form["submit"]
        extra.append(f"{name}={value}")

    return {
        "url": url,
        "field": form["file_input"],
        "extra": extra,
        "method": form.get("method") or "POST",
        "enctype": form.get("enctype") or "",
    }


def format_exec_form_shell(parsed: dict) -> str:
    """Emit zsh assignments safe for eval."""
    url = parsed.get("url") or ""
    field = parsed.get("field") or "file"
    lines = [
        f"_UPSH_URL={shlex.quote(url)}",
        f"_UPSH_FIELD={shlex.quote(field)}",
        "_UPSH_EXTRA=()",
    ]
    for item in parsed.get("extra") or []:
        lines.append(f"_UPSH_EXTRA+=({shlex.quote(item)})")
    return "\n".join(lines) + "\n"
