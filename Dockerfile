FROM portus.cs.int:5000/prod/cs-dbuild-capps
ARG destEnv

RUN echo "deb http://10.12.1.225/public xenial $destEnv" >> /etc/apt/sources.list
RUN printf "Package: * \nPin: release a=xenial, o=10.12.1.225 \nPin-Priority: 1600 \n" > /etc/apt/preferences
RUN apt-get update -y

