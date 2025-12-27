from bs4 import BeautifulSoup

def parse_html(html: str):
    soup = BeautifulSoup(html, "html.parser")
    return {
        "title": (soup.title.string.strip() if soup.title and soup.title.string else None),
        "meta_description": _meta(soup, "description"),
        "canonical": _link_rel(soup, "canonical"),
        "scripts": [s.get("src") for s in soup.find_all("script") if s.get("src")],
        "iframes": [i.get("src") for i in soup.find_all("iframe") if i.get("src")],
        "links": [a.get("href") for a in soup.find_all("a") if a.get("href")],
        "text": soup.get_text(" ", strip=True)
    }

def _meta(soup, name):
    tag = soup.find("meta", attrs={"name": name}) or soup.find("meta", attrs={"property": name})
    return tag.get("content").strip() if tag and tag.get("content") else None

def _link_rel(soup, rel):
    tag = soup.find("link", attrs={"rel": rel})
    return tag.get("href").strip() if tag and tag.get("href") else None
