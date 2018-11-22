FROM debian:stretch

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install curl gnupg apt-transport-https

RUN echo "deb https://apache.bintray.com/couchdb-deb stretch main" >> \
  /etc/apt/sources.list
RUN curl -L https://couchdb.apache.org/repo/bintray-pubkey.asc | apt-key add -

RUN apt-get -y update
RUN apt-get -y install \
  git \
  python-virtualenv \
  wget \
  sudo \
  net-tools \
  build-essential \
  ipython \
  python-setuptools \
  python-pip \
  python-dev \
  libssl-dev \
  libffi-dev \
  pkg-config \
  libssl-dev \
  libffi-dev \
  libxml2-dev \
  libxslt1-dev \
  libfreetype6-dev \
  libpng-dev \
  postgresql

EXPOSE 5985
WORKDIR /root
RUN git clone https://github.com/infobyte/faraday.git faraday-dev
WORKDIR ./faraday-dev
#RUN echo "psycopg2-binary" >> requirements.txt
RUN ./install.sh
COPY entrypoint.sh /root/entrypoint.sh

ENTRYPOINT ["/root/entrypoint.sh"]
