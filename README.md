# CryptoBench – RSA vs AES

Projekt zespołowy (Politechnika Śląska, Informatyka): **szyfrowanie algorytmem RSA i AES – implementacja i porównanie wydajności**.

Autorzy: Bartłomiej Zgóra, Artem Sapotnitsky

## Cel
Własne implementacje AES (128/192/256; CBC, CTR, GCM) i RSA (Miller-Rabin, OAEP, CRT) porównane z biblioteką referencyjną `cryptography` (OpenSSL) w powtarzalnych pomiarach, z dashboardem do wizualizacji wyników i trybem szyfrowania hybrydowego.

## Stos
Python 3.12+, pytest + wektory NIST, FastAPI, React + TypeScript + Recharts, Docker, GitHub Actions.

## Struktura (docelowo)
```
prelim/     wstępne testy przydatności (Efekt 1)
src/aes/    implementacja AES
src/rsa/    implementacja RSA
bench/      silnik benchmarków
api/        FastAPI
web/        dashboard React
docs/       dokumentacja, literatura
```

## Wstępne testy
```bash
cd prelim
pip install cryptography
python own_aes.py        # wektor FIPS-197 C.1
python prelim_bench.py   # pomiary -> results.json
```

## Harmonogram
| Etap | Termin |
|---|---|
| M0 Analiza i dobór technologii | 6.11.2026 |
| M1 Rdzeń AES + RSA | 29.11.2026 |
| M2 Benchmarki | 20.12.2026 |
| M3 API i dashboard | 17.01.2027 |
| M4 Raport i prezentacja | 31.01.2027 |

> Implementacje własne służą celom dydaktycznym i nie są przeznaczone do użytku produkcyjnego.
