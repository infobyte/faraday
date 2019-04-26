# This is an ubuntu with system packages required to run faraday
# It doesn't install the python dependencies. That is done in
# the gitlab CI job to avoid having old versions of packages.
# This is used to build registry.gitlab.com/faradaysec/faraday/faraday_testing_base
FROM ubuntu
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime
RUN echo $TZ > /etc/timezone
RUN apt-get update -qy
RUN apt-get -y install build-essential ipython python-setuptools python-pip python-dev pkg-config libssl-dev libffi-dev libxml2-dev libxslt1-dev libfreetype6-dev libpng-dev postgresql sudo libsasl2-dev libldap2-dev git
RUN apt-get install -y python-dev python-pip
