FROM portus.cs.int:5000/prod/cs-base

ARG destEnv
MAINTAINER Collective Sense "team@collective-sense.com"

ENV DEBIAN_FRONTEND=noninteractive
RUN echo "deb http://aptly.cs.int/public xenial $destEnv" >> /etc/apt/sources.list
RUN printf "Package: * \nPin: release a=xenial, o=aptly.cs.int \nPin-Priority: 1600 \n" > /etc/apt/preferences

RUN apt-get update && apt-get -y install pfring mq-broker nanomsg cslib suricata supervisor

RUN apt-get install -y python-pip && pip install supervisor-stdout

RUN groupadd -g 10003 suricata
RUN adduser --no-create-home --system --shell /bin/false --gecos 'suricata dedicated user' --uid 10003 --gid 10003 --disabled-password suricata

#RUN groupadd -g 10004 mq-broker
#RUN adduser --no-create-home --system --shell /bin/false --gecos 'mq-broker dedicated user' --uid 10004 --gid 10004 --disabled-password mq-broker

ADD files/supervisor_mq-broker.conf /etc/supervisor/conf.d/supervisor_mq-broker.conf
ADD files/supervisor_mq-broker2.conf /etc/supervisor/conf.d/supervisor_mq-broker2.conf
ADD files/supervisor_mq-broker-tatiana.conf /etc/supervisor/conf.d/supervisor_mq-broker-tatiana.conf
ADD files/supervisor_suricata.conf /etc/supervisor/conf.d/supervisor_suricata.conf
ADD files/supervisor_mq-broker-sarabi.conf /etc/supervisor/conf.d/supervisor_mq-broker-sarabi.conf
ADD files/supervisor_mq-broker-sarafina.conf /etc/supervisor/conf.d/supervisor_mq-broker-sarafina.conf
ADD files/supervisor_mq-broker-uru.conf /etc/supervisor/conf.d/supervisor_mq-broker-uru.conf
ADD files/supervisor_mq-broker-kovu.conf /etc/supervisor/conf.d/supervisor_mq-broker-kovu.conf

COPY files/docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

CMD /usr/bin/supervisord -n
