FROM docker-registry.cs.int/prod/cs-base
LABEL maintainer "devops@collective-sense.com"

ARG destEnv
ARG debVer

ENV DEBIAN_FRONTEND=noninteractive
RUN echo "deb http://aptly.cs.int/public xenial $destEnv" >> /etc/apt/sources.list
RUN printf "Package: * \nPin: release a=xenial, o=aptly.cs.int \nPin-Priority: 1600 \n" > /etc/apt/preferences

RUN apt-get update \
    && apt-get -y install \
         pfring \
         libnanomsg5 \
         cslib \
         suricata=${debVer} \
     && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10003 suricata
RUN adduser --no-create-home --system --shell /bin/false --gecos 'suricata dedicated user' --uid 10003 --gid 10003 --disabled-password suricata

COPY files/version.sh /version.sh
RUN ln -s /version.sh /usr/bin/version

COPY files/docker-entrypoint.sh /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
