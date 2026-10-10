#!/usr/bin/env python3
"""
Generează raportul PDF pentru o perioadă, pe baza dovezilor colectate de monitor.py.

Verifică pentru fiecare înregistrare:
  - hash-ul manifestului (față de jurnal),
  - hash-urile capturii și HTML-ului (față de manifest),
  - continuitatea lanțului de hash-uri,
  - marca temporală RFC 3161 (openssl ts -verify), dacă există certificatele TSA.

Utilizare:
  python raport.py --tinta articol-exemplu --de 2026-10-01 --pana 2026-10-31
                   [--iesire raport.pdf] [--marcheaza]
"""
import argparse
import datetime as dt
import hashlib
import json
import subprocess
from pathlib import Path
from zoneinfo import ZoneInfo

from PIL import Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Image as RLImage, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

TZ = ZoneInfo("Europe/Bucharest")
CULORI = {"PREZENT": colors.HexColor("#1b7f3b"), "ABSENT": colors.HexColor("#b3261e"),
          "EROARE": colors.HexColor("#a15c00")}


# ---------- fonturi cu diacritice ----------
def inregistreaza_fonturi():
    candidati = [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
        ("/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf"),
    ]
    for normal, bold in candidati:
        if Path(normal).exists() and Path(bold).exists():
            pdfmetrics.registerFont(TTFont("F", normal))
            pdfmetrics.registerFont(TTFont("F-B", bold))
            pdfmetrics.registerFontFamily("F", normal="F", bold="F-B")
            return "F", "F-B"
    return "Helvetica", "Helvetica-Bold"  # fără diacritice corecte


# ---------- utilitare ----------
def sha256_fisier(cale: Path) -> str:
    h = hashlib.sha256()
    with open(cale, "rb") as f:
        for bloc in iter(lambda: f.read(65536), b""):
            h.update(bloc)
    return h.hexdigest()


def local(moment_utc: str) -> dt.datetime:
    return dt.datetime.fromisoformat(moment_utc).astimezone(TZ)


def fmt(d: dt.datetime) -> str:
    return d.strftime("%d.%m.%Y %H:%M:%S")


def durata(sec: float) -> str:
    sec = int(sec)
    z, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    parti = ([f"{z} z"] if z else []) + ([f"{h} h"] if h else []) + [f"{m} min"]
    return " ".join(parti)


def verifica_tsr(manifest: Path, tsa: dict, baza: Path):
    tsr = manifest.with_suffix(".tsr")
    if not tsr.exists():
        return None  # nu există marcă temporală
    ca = baza / tsa.get("ca_file", "")
    crt = baza / tsa.get("cert_file", "")
    if not ca.is_file():
        return None  # nu se poate verifica fără certificatul CA
    cmd = ["openssl", "ts", "-verify", "-in", str(tsr), "-data", str(manifest),
           "-CAfile", str(ca)]
    if crt.is_file():
        cmd += ["-untrusted", str(crt)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0 and "OK" in r.stdout


def verifica_jurnal(dir_tinta: Path, tsa: dict, baza: Path):
    """Citește tot jurnalul și verifică integritatea fiecărei intrări și a lanțului."""
    intrari = []
    hash_anterior = None
    with open(dir_tinta / "jurnal.jsonl", encoding="utf-8") as f:
        for linie in f:
            if not linie.strip():
                continue
            e = json.loads(linie)
            probleme = []
            cale_m = dir_tinta / e["director"] / "manifest.json"
            manifest = None
            if not cale_m.exists():
                probleme.append("manifest lipsă")
            else:
                if sha256_fisier(cale_m) != e["hash_manifest"]:
                    probleme.append("manifest modificat")
                manifest = json.loads(cale_m.read_text(encoding="utf-8"))
                for nume, h in manifest["fisiere_sha256"].items():
                    cale_f = dir_tinta / e["director"] / nume
                    if not cale_f.exists():
                        probleme.append(f"{nume} lipsă")
                    elif sha256_fisier(cale_f) != h:
                        probleme.append(f"{nume} modificat")
                if manifest.get("hash_manifest_anterior") != hash_anterior:
                    probleme.append("lanț întrerupt")
            e["tsa_valid"] = verifica_tsr(cale_m, tsa, baza) if cale_m.exists() else False
            if e["tsa_valid"] is False:
                probleme.append("marcă temporală invalidă")
            e["probleme"] = probleme
            e["manifest"] = manifest
            e["local"] = local(e["moment_utc"])
            hash_anterior = e["hash_manifest"]
            intrari.append(e)
    return intrari


def miniatura(png: Path, tmp: Path, latime_cm=16, inaltime_max_px=1400):
    """Decupează partea de sus a capturii full-page, pentru includere în raport."""
    img = Image.open(png)
    if img.height > inaltime_max_px:
        img = img.crop((0, 0, img.width, inaltime_max_px))
    img.convert("RGB").save(tmp, "JPEG", quality=80)
    lat = latime_cm * cm
    return RLImage(str(tmp), width=lat, height=lat * img.height / img.width)


# ---------- raport ----------
def construieste(args):
    cale_cfg = Path(args.config).resolve()
    cfg = json.loads(cale_cfg.read_text(encoding="utf-8"))
    baza = cale_cfg.parent
    tinta = next(t for t in cfg["tinte"] if t["nume"] == args.tinta)
    dir_tinta = baza / cfg["director_dovezi"] / tinta["nume"]
    interval = cfg["interval_minute"] * 60

    de = dt.datetime.fromisoformat(args.de).replace(tzinfo=TZ)
    pana = (dt.datetime.fromisoformat(args.pana) + dt.timedelta(days=1)).replace(tzinfo=TZ)

    toate = verifica_jurnal(dir_tinta, cfg["tsa"], baza)
    intrari = [e for e in toate if de <= e["local"] < pana]
    if not intrari:
        raise SystemExit("Nicio verificare în perioada selectată.")

    # --- statistici ---
    nr = {s: sum(1 for e in intrari if e["stare"] == s) for s in CULORI}
    cu_probleme = [e for e in intrari if e["probleme"]]
    tsa_ok = sum(1 for e in intrari if e["tsa_valid"])
    tsa_neverif = sum(1 for e in intrari if e["tsa_valid"] is None)

    # goluri: pauze între verificări consecutive mai mari de 1,5 × interval
    goluri = []
    for a, b in zip(intrari, intrari[1:]):
        dif = (b["local"] - a["local"]).total_seconds()
        if dif > 1.5 * interval:
            goluri.append((a["local"], b["local"], dif))
    # evenimente neconforme: absențe și erori
    neconforme = [e for e in intrari if e["stare"] != "PREZENT"]

    concluzie_ok = (nr["ABSENT"] == 0 and nr["EROARE"] == 0 and not goluri
                    and not cu_probleme)

    # --- stiluri ---
    font, font_b = inregistreaza_fonturi()
    ss = getSampleStyleSheet()
    st = {
        "titlu": ParagraphStyle("t", parent=ss["Title"], fontName=font_b, fontSize=17),
        "h": ParagraphStyle("h", parent=ss["Heading2"], fontName=font_b, fontSize=12,
                            spaceBefore=10, spaceAfter=4),
        "p": ParagraphStyle("p", parent=ss["Normal"], fontName=font, fontSize=9.5,
                            leading=13),
        "mic": ParagraphStyle("m", parent=ss["Normal"], fontName=font, fontSize=7.5,
                              leading=9.5),
        "centru": ParagraphStyle("c", parent=ss["Normal"], fontName=font, fontSize=8,
                                 alignment=TA_CENTER, textColor=colors.grey),
    }
    P = lambda t, s="p": Paragraph(t, st[s])

    def tabel(date, latimi, antet=True, marime=8):
        t = Table(date, colWidths=latimi, repeatRows=1 if antet else 0)
        stil = [("FONT", (0, 0), (-1, -1), font, marime),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#bbbbbb")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]
        if antet:
            stil += [("FONT", (0, 0), (-1, 0), font_b, marime),
                     ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef5"))]
        t.setStyle(TableStyle(stil))
        return t

    story = []
    story += [P("Raport de monitorizare a publicării", "titlu"),
              P(f"Generat la {fmt(dt.datetime.now(TZ))} (ora României)", "centru"),
              Spacer(1, 10)]

    # 1. Obiect
    story.append(P("1. Obiectul monitorizării", "h"))
    story.append(tabel([
        ["Adresă (URL)", P(tinta["url"], "mic")],
        ["Text verificat", P(tinta["text_cautat"], "mic")],
        ["Zonă verificată", tinta.get("selector") or "întreaga pagină"],
        ["Perioadă raport", f"{de:%d.%m.%Y} – {(pana - dt.timedelta(days=1)):%d.%m.%Y}"],
        ["Interval planificat", f"la fiecare {cfg['interval_minute']} minute"],
    ], [4 * cm, 13 * cm], antet=False, marime=9))

    # 2. Rezumat
    story.append(P("2. Rezumat", "h"))
    story.append(tabel([
        ["Prima verificare", fmt(intrari[0]["local"])],
        ["Ultima verificare", fmt(intrari[-1]["local"])],
        ["Total verificări", str(len(intrari))],
        ["Articol prezent", str(nr["PREZENT"])],
        ["Articol absent", str(nr["ABSENT"])],
        ["Erori de verificare", str(nr["EROARE"])],
        ["Pauze în monitorizare", str(len(goluri))],
        ["Mărci temporale valide", f"{tsa_ok} din {len(intrari)}"
         + (f" ({tsa_neverif} neverificabile)" if tsa_neverif else "")],
        ["Probleme de integritate", str(len(cu_probleme))],
    ], [6 * cm, 11 * cm], antet=False, marime=9))
    story.append(Spacer(1, 6))
    if concluzie_ok:
        concl = (f"În toate cele {len(intrari)} verificări efectuate între "
                 f"{fmt(intrari[0]['local'])} și {fmt(intrari[-1]['local'])}, articolul a "
                 "fost găsit pe pagină, fără pauze în monitorizare și fără probleme de "
                 "integritate a dovezilor.")
    else:
        concl = ("Au fost identificate abateri (absențe, erori, pauze sau probleme de "
                 "integritate), detaliate în secțiunea 4.")
    story.append(P(f"<b>Concluzie:</b> {concl}"))

    # 3. Metodologie
    story.append(P("3. Metodologie", "h"))
    story.append(P(
        "Pagina a fost accesată automat, la intervale fixe, cu un browser Chromium real "
        "(randare completă, inclusiv JavaScript). La fiecare accesare s-au salvat: captura "
        "integrală a paginii (PNG), codul HTML randat și un manifest JSON cu amprentele "
        "SHA-256 ale acestor fișiere. Fiecare manifest conține amprenta manifestului "
        "anterior, formând un lanț în care eliminarea sau modificarea oricărei verificări "
        "devine detectabilă. Pentru fiecare manifest s-a obținut o marcă temporală "
        f"RFC 3161 de la autoritatea <i>{cfg['tsa']['url']}</i>, care atestă că "
        "manifestul exista, nemodificat, la momentul indicat. La generarea raportului, "
        "toate amprentele, lanțul și mărcile temporale au fost reverificate."))

    # 4. Abateri
    story.append(P("4. Abateri", "h"))
    if not (goluri or neconforme or cu_probleme):
        story.append(P("Nu au fost identificate abateri."))
    if goluri:
        story.append(P("Pauze în monitorizare:"))
        story.append(tabel([["De la", "Până la", "Durată"]] +
                           [[fmt(a), fmt(b), durata(d)] for a, b, d in goluri],
                           [5.5 * cm, 5.5 * cm, 6 * cm]))
        story.append(Spacer(1, 6))
    if neconforme:
        story.append(P("Verificări în care articolul nu a fost confirmat:"))
        story.append(tabel([["Moment", "Stare", "HTTP", "Detalii"]] + [
            [fmt(e["local"]), e["stare"], str(e["status_http"] or "–"),
             P((e["manifest"] or {}).get("eroare") or "text negăsit pe pagină", "mic")]
            for e in neconforme], [4 * cm, 2.2 * cm, 1.5 * cm, 9.3 * cm]))
        story.append(Spacer(1, 6))
    if cu_probleme:
        story.append(P("Probleme de integritate:"))
        story.append(tabel([["Moment", "Director", "Probleme"]] + [
            [fmt(e["local"]), e["director"], P(", ".join(e["probleme"]), "mic")]
            for e in cu_probleme], [4 * cm, 4 * cm, 9 * cm]))

    # 5. Capturi
    tmp = dir_tinta / ".tmp_raport"
    tmp.mkdir(exist_ok=True)
    exemple = [("Prima verificare", intrari[0]), ("Ultima verificare", intrari[-1])]
    for i, (eticheta, e) in enumerate(exemple):
        png = dir_tinta / e["director"] / "pagina.png"
        if not png.exists():
            png = dir_tinta / e["director"] / "pagina.jpg"
        if png.exists():
            story.append(PageBreak())
            story.append(P(f"5.{i + 1}. Captură – {eticheta} ({fmt(e['local'])})", "h"))
            story.append(P(f"Amprentă SHA-256: {e['manifest']['fisiere_sha256'].get(png.name, '–')}",
                           "mic"))
            story.append(Spacer(1, 4))
            story.append(miniatura(png, tmp / f"m{i}.jpg"))

    # 6. Jurnal detaliat
    story.append(PageBreak())
    story.append(P("6. Jurnalul complet al verificărilor", "h"))
    rand = [["#", "Moment (ora RO)", "Stare", "HTTP", "Marcă temporală TSA", "Integr."]]
    for n, e in enumerate(intrari, 1):
        tsa_txt = e.get("tsa_timp") or "–"
        if e["tsa_valid"] is None and e.get("tsa_timp"):
            tsa_txt += " (neverif.)"
        rand.append([str(n), fmt(e["local"]), e["stare"], str(e["status_http"] or "–"),
                     tsa_txt, "OK" if not e["probleme"] else "!"])
    t = tabel(rand, [1 * cm, 3.6 * cm, 2 * cm, 1.2 * cm, 7.2 * cm, 1.4 * cm], marime=7)
    for n, e in enumerate(intrari, 1):
        t.setStyle(TableStyle([("TEXTCOLOR", (2, n), (2, n), CULORI[e["stare"]])]))
    story.append(t)
    story.append(Spacer(1, 8))
    story.append(P(f"Amprenta SHA-256 a jurnalului sursă: "
                   f"{sha256_fisier(dir_tinta / 'jurnal.jsonl')}", "mic"))

    def subsol(canv, doc):
        canv.saveState()
        canv.setFont(font, 7)
        canv.setFillColor(colors.grey)
        canv.drawString(2 * cm, 1.2 * cm, f"{tinta['nume']} – raport monitorizare")
        canv.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Pagina {doc.page}")
        canv.restoreState()

    iesire = Path(args.iesire or f"raport_{tinta['nume']}_{args.de}_{args.pana}.pdf")
    doc = SimpleDocTemplate(str(iesire), pagesize=A4, leftMargin=2 * cm,
                            rightMargin=2 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                            title="Raport de monitorizare a publicării")
    doc.build(story, onFirstPage=subsol, onLaterPages=subsol)
    for f in tmp.glob("*"):
        f.unlink()
    tmp.rmdir()
    print(f"Raport generat: {iesire}")

    if args.marcheaza:
        import monitor
        ts = monitor.marca_temporala(iesire, cfg["tsa"])
        print(f"Marcă temporală raport: {ts['tsa_timp'] or ts['tsa_eroare']}")


def main():
    ap = argparse.ArgumentParser(description="Raport PDF monitorizare articol")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--tinta", required=True)
    ap.add_argument("--de", required=True, help="AAAA-LL-ZZ (inclusiv)")
    ap.add_argument("--pana", required=True, help="AAAA-LL-ZZ (inclusiv)")
    ap.add_argument("--iesire", help="fișierul PDF rezultat")
    ap.add_argument("--marcheaza", action="store_true",
                    help="obține și o marcă temporală pentru PDF-ul generat")
    construieste(ap.parse_args())


if __name__ == "__main__":
    main()
