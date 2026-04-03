#!/bin/bash

docker-compose down -v
docker-compose up -d --build

echo "[+] Lab reset done"
