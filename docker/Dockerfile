FROM conda/miniconda3

WORKDIR /src/stringsifter
COPY . /src/stringsifter

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    gcc \
    g++ \
    less && \
    conda update -n base -c defaults conda && \
    pip install -r ./requirements.txt

RUN pip install -e /src/stringsifter
