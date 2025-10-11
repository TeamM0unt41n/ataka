FROM sagemath/sagemath:latest

RUN sage -pip install --no-cache-dir --upgrade pip
RUN sage -pip install --no-cache-dir pwntools cryptography beautifulsoup4 requests pycryptodome

WORKDIR /exploit
ENV PYTHONUNBUFFERED=1
ARG DEBIAN_FRONTEND=noninteractive
ENV DEBIAN_FRONTEND=${DEBIAN_FRONTEND}

COPY requirements.txt .
RUN sage -pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "sage", "-python", "exploit.py" ]

