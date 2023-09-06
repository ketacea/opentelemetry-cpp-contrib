FROM debian:10.13

ARG GRPC_VERSION="1.49.2"
ARG OPENTELEMETRY_VERSION="1.8.1"
ARG PCRE_VERSION="8.44"
ARG NGINX_VERSION="1.21.4"

RUN apt-get -y update && apt-get -y upgrade && apt-get -y dist-upgrade

RUN apt-get install -qq -y --ignore-missing \
        build-essential                             \
        curl                                            \
        git                                                 \
        make                                            \
        pkg-config                                      \
        protobuf-compiler                           \
        libprotobuf-dev                         \
        python                                          \
        sudo                                            \
        tar                                                 \
        zip                                                 \
        unzip                                           \
        wget                                            \
    cmake

RUN apt-get install -y \
    lcov    \
    m4                                      \
    autoconf                                \
    automake                                \
    libtool                                 \
    default-jre

RUN git clone --shallow-submodules --depth 1 --recurse-submodules -b v${GRPC_VERSION} \
      https://github.com/grpc/grpc \
      && cd grpc \
      && mkdir -p cmake/build \
      && cd cmake/build \
      && cmake \
        -DgRPC_INSTALL=ON \
        -DgRPC_BUILD_TESTS=OFF \
        -DCMAKE_INSTALL_PREFIX=/install \
        -DCMAKE_BUILD_TYPE=Release \
        -DgRPC_BUILD_GRPC_NODE_PLUGIN=OFF \
        -DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN=OFF \
        -DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF \
        -DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF \
        -DgRPC_BUILD_GRPC_PYTHON_PLUGIN=OFF \
        -DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF \
        -DCMAKE_CXX_STANDARD=17 \
        ../.. \
      && make -j2 \
      && make install

RUN apt-get install -y curl libcurl4-openssl-dev

RUN cd /opt \
  && git clone --shallow-submodules --depth 1 --recurse-submodules -b v${OPENTELEMETRY_VERSION} \
  https://github.com/open-telemetry/opentelemetry-cpp.git \
  && cd opentelemetry-cpp \
  && mkdir build \
  && cd build \
  && cmake -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/install \
    -DCMAKE_PREFIX_PATH=/install \
    -DWITH_OTLP=ON \
    -DWITH_OTLP_GRPC=ON \
    -DWITH_OTLP_HTTP=OFF \
    -DBUILD_TESTING=OFF \
    -DWITH_EXAMPLES=OFF \
    -DCMAKE_CXX_STANDARD=17 \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    .. \
  && make -j2 \
  && make install

RUN cd /  \
&& mkdir -p dependencies/pcre/${PCRE_VERSION}/ \
&& wget https://ftp.exim.org/pub/pcre/pcre-${PCRE_VERSION}.tar.gz --no-check-certificate \
&& tar -xvf pcre-${PCRE_VERSION}.tar.gz \
&& cd pcre-8.44 \
&& ./configure --prefix=/dependencies/pcre/${PCRE_VERSION} --enable-jit \
&& make && make install \
&& cd .. && rm -rf ${PCRE_VERSION}.tar.gz && rm -rf pcre-${PCRE_VERSION}

RUN apt-get install -y libpcre3-dev
RUN mkdir -p otel-nginx/build && mkdir -p otel-nginx/src
COPY src otel-nginx/src/
COPY CMakeLists.txt nginx.cmake otel-nginx/
RUN cd otel-nginx/build \
  && cmake -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=/install \
    -DCMAKE_INSTALL_PREFIX=/usr/share/nginx/modules \
    .. \
  && make -j2 \
  && make install