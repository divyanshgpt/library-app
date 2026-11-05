"""
Web version of the Library Management System.

Run:   python library_web.py            then open http://localhost:8000
Demo:  python library_web.py --demo     (adds sample books and two sample members)

Needs nothing but Python. It uses database.py exactly as it is, so every rule
(fines, 3-book limit, password rules...) behaves the same as in the desktop app.
"""

import json
import sys
import secrets
import time
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from datetime import date
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import database as db

PORT = 8000
PAGE = Path(__file__).with_name("index.html")
SESSIONS = {}                      # session id -> user dict (kept in memory)
PUBLIC, MEMBER, LIBRARIAN = 0, 1, 2

# ---- news (needs internet; the page still works without it) ----
# Feeds are tried in order. Change or add any RSS address you like.
NEWS_FEEDS = [
    "https://www.theguardian.com/books/rss",
    "https://feeds.bbci.co.uk/news/entertainment_and_arts/rss.xml",
]
NEWS_CACHE = {"time": 0, "items": []}
NEWS_MINUTES = 30                  # how long to reuse the last fetch

FACTS = [
    "The Library of Alexandria is thought to have been one of the largest libraries of the ancient world.",
    "The Library of Congress in Washington, D.C. is widely regarded as the largest library in the world by collection size.",
    "Reading for just six minutes has been reported to reduce stress levels in a well-known University of Sussex study.",
    "The word 'library' comes from the Latin 'liber', meaning book.",
    "The first public lending library in the U.S. is often credited to Benjamin Franklin's Library Company of Philadelphia (1731).",
    "The Dewey Decimal System, created in 1876, is still used by many libraries to organise non-fiction books.",
    "Nalanda in Bihar was home to one of the world's earliest residential universities, famed for its huge library.",
    "Regular readers are often reported to sleep better and show slower memory decline in later life.",
    "National Library Week and Library Week are celebrated in many countries, and in India National Library Week runs in November.",
    "Books kept in a cool, dry place with steady humidity can last for centuries.",
    "To take a book off a tight shelf, push the neighbours back and grip the spine, rather than hooking the top edge.",
    "Short loan periods like 14 days help more members get a turn with popular books.",
]


def fetch_news():
    """Latest headlines from the first feed that works. Cached so we don't hammer the site."""
    if NEWS_CACHE["items"] and time.time() - NEWS_CACHE["time"] < NEWS_MINUTES * 60:
        return NEWS_CACHE["items"]
    for url in NEWS_FEEDS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Librarify/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                root = ET.fromstring(resp.read())
        except Exception:
            continue
        source = (root.findtext("channel/title") or "News").strip()
        items = []
        for it in root.iter("item"):
            title = (it.findtext("title") or "").strip()
            link = (it.findtext("link") or "").strip()
            if title and link.startswith(("http://", "https://")):
                items.append({"title": title, "link": link, "source": source,
                              "date": (it.findtext("pubDate") or "")[:16]})
            if len(items) == 6:
                break
        if items:
            NEWS_CACHE.update(time=time.time(), items=items)
            return items
    if NEWS_CACHE["items"]:                        # offline: show the older headlines
        return NEWS_CACHE["items"]
    raise db.LibraryError("Couldn't load news. Check your internet connection.")


def fact_of_the_day():
    return FACTS[date.today().toordinal() % len(FACTS)]


def public_user(u):
    return {k: u[k] for k in ("id", "username", "name", "role")}


def login(u, d):
    user = db.authenticate(d.get("username", ""), d.get("password", ""))
    if user is None:
        raise db.LibraryError("Wrong username or password.")
    sid = secrets.token_urlsafe(24)
    SESSIONS[sid] = user
    return {"user": public_user(user), "_sid": sid}


def logout(u, d):
    return {"_sid": ""}


def books(u, d):
    out = []
    for b in db.list_books(d.get("search", ""), d.get("category", "All")):
        status, due, state = "Available", "", "free"
        if b["holder_username"]:
            due = b["due_date"]
            state = "overdue" if due < db.today() else "out"
            if u["role"] == "librarian":
                status = f"Issued to {b['holder_name']} ({b['holder_username']})"
            elif b["holder_id"] == u["id"]:
                status = "Issued to you"
            else:
                status = "Issued"          # members never see who else has a book
        out.append({"book_id": b["book_id"], "title": b["title"], "author": b["author"],
                    "category": b["category"], "status": status, "due": due, "state": state})
    return out


def loans(u, d):
    mine = u["role"] != "librarian"
    return db.loans(u["id"] if mine else None, d.get("mode", "active"))


ACTIONS = {
    "hint":        (PUBLIC, lambda u, d: {"default": db.default_password_unchanged()}),
    "login":       (PUBLIC, login),
    "logout":      (PUBLIC, logout),
    "signup":      (PUBLIC, lambda u, d: db.create_user(d["username"], d["password"], d["name"], d["phone"])),
    "me":          (MEMBER, lambda u, d: public_user(u)),
    "change_pw":   (MEMBER, lambda u, d: db.change_password(u["id"], d["current"], d["new"])),
    "books":       (MEMBER, books),
    "categories":  (MEMBER, lambda u, d: db.list_categories()),
    "loans":       (MEMBER, loans),
    "stats":       (LIBRARIAN, lambda u, d: db.stats()),
    "insights":    (LIBRARIAN, lambda u, d: {**db.insights(), "fact": fact_of_the_day()}),
    "news":        (LIBRARIAN, lambda u, d: fetch_news()),
    "add_book":    (LIBRARIAN, lambda u, d: db.add_book(d["book_id"], d["title"], d["author"], d["category"])),
    "edit_book":   (LIBRARIAN, lambda u, d: db.update_book(d["book_id"], d["title"], d["author"], d["category"])),
    "delete_book": (LIBRARIAN, lambda u, d: db.delete_book(d["book_id"])),
    "issue":       (LIBRARIAN, lambda u, d: {"due": db.issue_book(d["book_id"], d["username"])}),
    "return":      (LIBRARIAN, lambda u, d: db.return_book(d["book_id"])),
    "members":     (LIBRARIAN, lambda u, d: [dict(m) for m in db.list_members()]),
    "reset_pw":    (LIBRARIAN, lambda u, d: db.reset_password(int(d["id"]), d["new"])),
    "remove":      (LIBRARIAN, lambda u, d: db.remove_member(int(d["id"]))),
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body, kind="application/json", sid=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        if sid is not None:
            self.send_header("Set-Cookie", f"sid={sid}; HttpOnly; SameSite=Strict; Path=/"
                             + ("; Max-Age=0" if sid == "" else ""))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply(200, PAGE.read_bytes(), "text/html; charset=utf-8")

    def do_POST(self):
        name = self.path.removeprefix("/api/")
        if name not in ACTIONS:
            return self.reply(404, {"error": "Unknown action."})
        level, fn = ACTIONS[name]
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        sid = cookie["sid"].value if "sid" in cookie else None
        user = SESSIONS.get(sid)
        if level >= MEMBER and user is None:
            return self.reply(401, {"error": "Please log in again."})
        if level == LIBRARIAN and user["role"] != "librarian":
            return self.reply(403, {"error": "Librarians only."})
        try:
            size = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(size) or b"{}")
            result = fn(user, data)
        except db.LibraryError as problem:
            return self.reply(400, {"error": str(problem)})
        except KeyError as missing:
            return self.reply(400, {"error": f"Missing field {missing}."})
        except Exception as bug:
            return self.reply(500, {"error": f"{type(bug).__name__}: {bug}"})
        new_sid = None
        if isinstance(result, dict) and "_sid" in result:
            new_sid = result.pop("_sid")
            if new_sid == "":
                SESSIONS.pop(sid, None)
        self.reply(200, result if result is not None else {}, sid=new_sid)


def main():
    db.init_db()
    if "--demo" in sys.argv:
        db.seed_demo()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Library running at http://localhost:{PORT}   (Ctrl+C to stop)")
    webbrowser.open(f"http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
