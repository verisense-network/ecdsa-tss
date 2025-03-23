#!/bin/bash

# 读取 .env 中的 PORT
PORT=$(grep PORT .env | cut -d '=' -f2)

echo "Building and running Go server on port $PORT..."

docker-compose up --build