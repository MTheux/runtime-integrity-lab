# Reproducible Linux environment for the lab (works from macOS/Windows too).
#   docker build -t runtime-integrity-lab .
#   docker run --rm runtime-integrity-lab
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY . /lab
RUN chmod +x run_demo.sh patcher/nop_enforcement.py
CMD ["./run_demo.sh"]
