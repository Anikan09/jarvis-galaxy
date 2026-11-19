"""Demo mode: the made-up coffee roaster's day."""
EVENTS = [
    {"title": "Cupping: holiday blend final", "start": "09:30", "end": "10:30", "calendar": "google"},
    {"title": "Call with Finca Aurora", "start": "12:00", "end": "12:30", "calendar": "google"},
    {"title": "Photo shoot, holiday blend", "start": "14:00", "end": "16:00", "calendar": "apple"},
]
_m = lambda name, addr, subject, snippet, cat: {"from_name": name, "from_addr": addr, "subject": subject, "snippet": snippet,
                                                "category": cat, "why": "", "received": ""}
EMAILS = [
    _m("Priya Nair", "priya@example.com", "Q4 green bean contract: your view?", "Need your call on Finca Aurora vs Rio Verde by Friday...", "needs_reply"),
    _m("Lena Vogel", "lena@example.com", "Newsletter draft for 1 December", "Here's the draft for the holiday blend launch, photos to follow...", "needs_reply"),
    _m("Print & Pack Ltd", "billing@example.org", "Invoice 2211 due 28 November", "Your invoice for 300 holiday blend bags is attached...", "action"),
    _m("Coffee Weekly", "news@example.org", "This week in specialty coffee", "Harvest reports from Colombia and Ethiopia...", "fyi"),
]
