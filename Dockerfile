FROM debian:stretch

RUN apt-get -y update && apt-get -y upgrade
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

WORKDIR /root
RUN git clone https://github.com/infobyte/faraday.git faraday-dev
WORKDIR ./faraday-dev
RUN ./install.sh
COPY entrypoint.sh /root/entrypoint.sh

EXPOSE 5985

ENTRYPOINT ["/root/entrypoint.sh"]
