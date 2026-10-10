# Monitorizare publicare — anunț proiect de fuziune Citadin Zalău

Verificare automată, la fiecare oră, rulată de GitHub Actions (terț independent de hostingul site-ului):

- pagina anunțului și lista de anunțuri de pe www.citadinzalau.ro: captură completă (JPEG), HTML randat, prezența titlului „ANUNȚ PRIVIND PUBLICAREA PROIECTULUI DE FUZIUNE";
- PDF-ul proiectului de fuziune: HTTP 200, semnătura `%PDF-` și amprenta SHA-256 identică cu documentul publicat pe 29.09.2026 (`c3d1cba39aa9f8aebae44d029b6769822b92d37c38cc3bd7a7a4f9316000bab3`).

Fiecare verificare are un `manifest.json` cu amprentele fișierelor, legat de manifestul anterior (lanț de hash-uri), și o marcă temporală RFC 3161 (`manifest.tsr`, FreeTSA). Commit-urile GitHub adaugă o a doua marcă de timp, independentă.

Verificare de către oricine, pentru o înregistrare:

```bash
cd dovezi/anunt-fuziune/<AAAALLZZ_HHMMSS>
sha256sum *                                   # compară cu manifest.json
openssl ts -verify -in manifest.tsr -data manifest.json -CAfile ../../../tsa/cacert.pem -untrusted ../../../tsa/tsa.crt
```

Raport PDF pe o perioadă: `python raport.py --tinta anunt-fuziune --de 2026-10-10 --pana 2026-10-29 --marcheaza`.
