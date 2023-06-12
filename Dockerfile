FROM python:3

RUN apt-get -y install aircrack-ng
RUN apt-get -y install hcxtools

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "./pwnagotchi-helper.py" ]
