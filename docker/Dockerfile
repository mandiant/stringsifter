FROM python:3.9

WORKDIR /src/stringsifter
COPY . /src/stringsifter

RUN pip install -r requirements.txt
RUN pip install -e /src/stringsifter

CMD [ "/bin/bash" ]
