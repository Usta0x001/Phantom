@echo off
REM ==========================================================
REM  Phantom Thesis — Compile Script
REM  Requires: TeX Live 2023+ or MiKTeX with biber
REM ==========================================================
echo [1/4] First pdflatex pass...
pdflatex -interaction=nonstopmode main.tex

echo [2/4] Biber (bibliography)...
biber main

echo [3/4] Second pdflatex pass...
pdflatex -interaction=nonstopmode main.tex

echo [4/4] Third pdflatex pass (for final ToC/LoF/LoT)...
pdflatex -interaction=nonstopmode main.tex

echo.
echo Done! Output: main.pdf
pause
