#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"
printf '\n[SIXVOID] Preparando ambiente Termux...\n'
pkg update -y
pkg install nodejs-lts -y
npm install --no-bin-links
if [ ! -f .env ]; then cp .env.example .env; fi
printf '\n[SIXVOID] Instalação concluída. Edite o arquivo .env e execute: npm start\n'
