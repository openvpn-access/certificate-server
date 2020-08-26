# Must be built from the parent dir

FROM alpine:edge

# Grab build tools
ENV BUILD_ONLY_DEPENDENCIES cmake doxygen openssl-dev curl-dev

RUN apk update \
    && apk upgrade --update-cache --available \
    && apk add --update $BUILD_ONLY_DEPENDENCIES alpine-sdk openssl libcurl jq

WORKDIR /tmp

# Build Pistache
RUN git clone https://github.com/oktal/pistache.git
WORKDIR /tmp/pistache
RUN git checkout 718aabba8b009d112f045bed35e92ef3112d7da0
RUN git submodule update --init
RUN mkdir -p {build,prefix}
WORKDIR /tmp/pistache/build
RUN cmake -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DPISTACHE_BUILD_EXAMPLES=false \
        -DPISTACHE_BUILD_TESTS=false \
        -DPISTACHE_BUILD_DOCS=false \
        -DPISTACHE_USE_SSL=true \
        -DPISTACHE_INSTALL=true \
        ../
RUN cmake --build . --target pistache_shared
RUN make install

# Build certificate server
COPY . /opt/app
RUN mkdir -p /config

WORKDIR /opt/app
RUN cp ./config/default.json /config/certificate-server.json

RUN mkdir build
WORKDIR /opt/app/build
RUN cmake -DCMAKE_BUILD_TYPE=Release -DGENERATE_DOCUMENTATION=false ..
RUN cmake --build . --target certificate_server

# Cleanup certificate_server build files
WORKDIR /tmp
RUN cp /opt/app/build/certificate_server .
RUN rm -rf /opt/app/*
RUN mv ./certificate_server /opt/app

# Cleanup tmp
WORKDIR /
RUN rm -rf /tmp/*

# Remove build packages
RUN apk del $BUILD_ONLY_DEPENDENCIES

WORKDIR /opt/app
COPY ./docker/docker-entrypoint.sh /opt/app/docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh

COPY ./config/default.json /opt/app/default-config.json

ENTRYPOINT /bin/sh /opt/app/docker-entrypoint.sh
