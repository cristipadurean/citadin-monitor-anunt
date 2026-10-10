#!/usr/bin/env python3
"""
Monitorizare prezență articol pe o pagină web.

Rulat periodic (cron / Task Scheduler). La fiecare rulare, pentru fiecare țintă din config:
  1. deschide pagina într-un browser real (Chromium headless),
  2. salvează captura full-page (PNG) și HTML-ul randat,
  3. verifică prezența textului căutat,
  4. scrie un manifest JSON cu hash-urile SHA-256 ale fișierelor,
     legat de manifestul anterior (lanț de hash-uri -> ștergerea/modificarea
     unei verificări devine detectabilă),
  5. obține o marcă temporală RFC 3161 pe manifest de la TSA,
  6. adaugă o linie în jurnal.jsonl.

Utilizare:  python monitor.py [--config config.json] [--tinta nume]
"""
import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

VERSIUNE = "1.0"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def sha256_fisier(cale: Path) -> str:
    h = hashlib.sha256()
    with open(cale, "rb") as f:
        for bloc in iter(lambda: f.read(65536), b""):
            h.update(bloc)
    return h.hexdigest()


def normalizeaza(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().lower()


def ultima_intrare(jurnal: Path):
    if not jurnal.exists():
        return None
    ultima = None
    with open(jurnal, encoding="utf-8") as f:
        for linie in f:
            if linie.strip():
                ultima = json.loads(linie)
    return ultima


def captureaza_fisier(tinta: dict, dest: Path) -> dict:
    """Ținte de tip "fisier" (ex. PDF): descarcă documentul și îl păstrează integral.
    „prezent" = HTTP < 400, semnătura așteptată la început și, dacă e setat în config,
    același SHA-256 ca documentul publicat inițial (dovedește că nu a fost înlocuit)."""
    rez = {"status_http": None, "url_final": None, "prezent": False, "eroare": None}
    try:
        r = requests.get(tinta["url"], headers={"User-Agent": USER_AGENT}, timeout=60)
        rez["status_http"] = r.status_code
        rez["url_final"] = r.url
        nume = tinta.get("nume_fisier", "document.bin")
        hash_doc = hashlib.sha256(r.content).hexdigest()
        rez["extra"] = {"document_sha256": hash_doc, "document_octeti": len(r.content)}
        # "la_schimbare": documentul integral doar la prima verificare și când amprenta se schimbă
        ultim = dest.parent / ".ultim_document_sha256"
        if (tinta.get("pastreaza_document") != "la_schimbare" or not ultim.exists()
                or ultim.read_text().strip() != hash_doc):
            (dest / nume).write_bytes(r.content)
            ultim.write_text(hash_doc)
        (dest / "antete.json").write_text(json.dumps(dict(r.headers), ensure_ascii=False, indent=2),
                                         encoding="utf-8")
        semnatura = tinta.get("semnatura", "%PDF-").encode("latin-1")
        ok = r.status_code < 400 and r.content.startswith(semnatura)
        asteptat = tinta.get("sha256_asteptat")
        if ok and asteptat:
            ok = hashlib.sha256(r.content).hexdigest() == asteptat.lower()
        rez["prezent"] = ok
    except Exception as e:
        rez["eroare"] = f"{type(e).__name__}: {e}"[:500]
    return rez


def captureaza(tinta: dict, dest: Path) -> dict:
    """Deschide pagina și salvează dovezile. Nu aruncă excepții: întoarce rezultatul."""
    if tinta.get("tip") == "fisier":
        return captureaza_fisier(tinta, dest)
    rez = {"status_http": None, "url_final": None, "prezent": False, "eroare": None}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(
                viewport={"width": 1366, "height": 900},
                locale="ro-RO",
                user_agent=USER_AGENT,
            )
            page = ctx.new_page()
            raspuns = page.goto(tinta["url"], wait_until="load", timeout=60000)
            page.wait_for_timeout(3000)  # lasă scripturile să termine randarea

            rez["status_http"] = raspuns.status if raspuns else None
            rez["url_final"] = page.url

            selector = tinta.get("selector")
            if selector:
                loc = page.locator(selector)
                text = loc.first.inner_text() if loc.count() > 0 else ""
            else:
                text = page.inner_text("body")
            rez["prezent"] = normalizeaza(tinta["text_cautat"]) in normalizeaza(text)

            (dest / "pagina.html").write_text(page.content(), encoding="utf-8")
            if tinta.get("captura") == "jpeg":  # mai mic, pentru stocare în git (GitHub Actions)
                page.screenshot(path=str(dest / "pagina.jpg"), full_page=True, type="jpeg", quality=55)
            else:
                page.screenshot(path=str(dest / "pagina.png"), full_page=True)
            browser.close()
    except Exception as e:  # eșec al monitorului != articol absent
        rez["eroare"] = f"{type(e).__name__}: {e}"[:500]
    return rez


def marca_temporala(fisier: Path, tsa: dict) -> dict:
    """Cere o marcă temporală RFC 3161 pentru fișier. Salvează .tsq și .tsr lângă el."""
    tsq = fisier.with_suffix(".tsq")
    tsr = fisier.with_suffix(".tsr")
    try:
        subprocess.run(
            ["openssl", "ts", "-query", "-data", str(fisier), "-sha256", "-cert",
             "-out", str(tsq)],
            check=True, capture_output=True,
        )
        auth = (tsa["utilizator"], tsa["parola"]) if tsa.get("utilizator") else None
        r = requests.post(
            tsa["url"], data=tsq.read_bytes(), auth=auth, timeout=30,
            headers={"Content-Type": "application/timestamp-query"},
        )
        r.raise_for_status()
        tsr.write_bytes(r.content)
        info = subprocess.run(
            ["openssl", "ts", "-reply", "-in", str(tsr), "-text"],
            check=True, capture_output=True, text=True,
        ).stdout
        timp = re.search(r"Time stamp:\s*(.+)", info)
        stare = re.search(r"Status:\s*(.+)", info)
        return {
            "tsa_timp": timp.group(1).strip() if timp else None,
            "tsa_status": stare.group(1).strip() if stare else None,
            "tsa_eroare": None,
        }
    except Exception as e:
        return {"tsa_timp": None, "tsa_status": None,
                "tsa_eroare": f"{type(e).__name__}: {e}"[:300]}


def verifica_tinta(tinta: dict, cfg: dict, baza: Path):
    dir_tinta = baza / cfg["director_dovezi"] / tinta["nume"]
    dir_tinta.mkdir(parents=True, exist_ok=True)
    jurnal = dir_tinta / "jurnal.jsonl"

    acum = dt.datetime.now(dt.timezone.utc)
    dest = dir_tinta / acum.strftime("%Y%m%d_%H%M%S")
    dest.mkdir()

    rez = captureaza(tinta, dest)
    if rez["eroare"]:
        stare = "EROARE"
    elif rez["prezent"] and rez["status_http"] and rez["status_http"] < 400:
        stare = "PREZENT"
    else:
        stare = "ABSENT"

    fisiere = {}
    for nume in ("pagina.png", "pagina.jpg", "pagina.html", tinta.get("nume_fisier", "document.bin"), "antete.json"):
        cale = dest / nume
        if cale.exists():
            fisiere[nume] = sha256_fisier(cale)

    anterior = ultima_intrare(jurnal)
    manifest = {
        "versiune_monitor": VERSIUNE,
        "tinta": tinta["nume"],
        "url": tinta["url"],
        "text_cautat": tinta["text_cautat"],
        "selector": tinta.get("selector"),
        "moment_utc": acum.isoformat(),
        "status_http": rez["status_http"],
        "url_final": rez["url_final"],
        "stare": stare,
        "eroare": rez["eroare"],
        "fisiere_sha256": fisiere,
        "hash_manifest_anterior": anterior["hash_manifest"] if anterior else None,
        **rez.get("extra", {}),
    }
    cale_manifest = dest / "manifest.json"
    cale_manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    hash_manifest = sha256_fisier(cale_manifest)

    ts = marca_temporala(cale_manifest, cfg["tsa"])

    intrare = {
        "moment_utc": manifest["moment_utc"],
        "director": dest.name,
        "stare": stare,
        "status_http": rez["status_http"],
        "hash_manifest": hash_manifest,
        **ts,
    }
    with open(jurnal, "a", encoding="utf-8") as f:
        f.write(json.dumps(intrare, ensure_ascii=False) + "\n")

    print(f"[{acum:%Y-%m-%d %H:%M:%S} UTC] {tinta['nume']}: {stare}"
          f" (HTTP {rez['status_http']}, TSA: {ts['tsa_status'] or ts['tsa_eroare']})")


def main():
    ap = argparse.ArgumentParser(description="Monitorizare prezență articol")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--tinta", help="rulează doar ținta cu acest nume")
    args = ap.parse_args()

    cale_cfg = Path(args.config).resolve()
    cfg = json.loads(cale_cfg.read_text(encoding="utf-8"))
    baza = cale_cfg.parent

    tinte = [t for t in cfg["tinte"] if not args.tinta or t["nume"] == args.tinta]
    if not tinte:
        sys.exit(f"Nicio țintă găsită: {args.tinta}")
    for t in tinte:
        verifica_tinta(t, cfg, baza)


if __name__ == "__main__":
    main()
