FROM debian:10.13
ENV DEBIAN_FRONTEND noninteractive

USER root

RUN apt-get -y update && apt-get -y upgrade && apt-get -y dist-upgrade
RUN apt-get install -qq -y --ignore-missing \
	build-essential		                    \
	curl			                        \
	git			                            \
	make			                        \
	pkg-config		                        \
	protobuf-compiler	                    \
	libprotobuf-dev                         \
	python			                        \
	sudo			                        \
	tar			                            \
	zip			                            \
	unzip			                        \
	wget			                        \
    cmake

RUN apt-get install -y                      \
    lcov                                    \
    m4                                      \
    autoconf                                \
    automake                                \
    libtool                                 \
    curl                                    \
    libcurl4-openssl-dev                    \
    libssl-dev                              \
    default-jre

# The following arguments would be passed from docker-compose.yml
ARG GRPC_VERSION="1.49.2"
ARG OPENTELEMETRY_VERSION="1.8.1"
ARG BOOST_VERSION="1.75.0"
ARG BOOST_FILENAME="boost_1_75_0"
ARG APR_VERSION="1.7.0"
ARG EXPAT_VERSION="2.3.0"
ARG EXPAT_RVERSION="R_2_3_0"
ARG APRUTIL_VERSION="1.6.1"
ARG LOG4CXX_VERSION="0.11.0"
ARG GTEST_VERSION="1.10.0"
ARG PCRE_VERSION="8.44"
ARG NGINX_VERSION="1.21.4"

# install cmake
RUN mkdir /cmake/ \
    && cd /cmake \
    && wget https://cmake.org/files/v3.27/cmake-3.27.1-linux-x86_64.sh \
    && mkdir /opt/cmake \
    && sh cmake-3.27.1-linux-x86_64.sh --prefix=/opt/cmake --skip-license \
    && apt purge --auto-remove -y cmake \
    && ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake \
    && ln -s /opt/cmake/bin/cmake /usr/bin/cmake

#install Apr
RUN mkdir -p dependencies/apr/${APR_VERSION} \
    && wget https://archive.apache.org/dist/apr/apr-${APR_VERSION}.tar.gz --no-check-certificate \
    && tar -xf apr-${APR_VERSION}.tar.gz \
    && cd apr-${APR_VERSION} \
    && ./configure --prefix=/dependencies/apr/${APR_VERSION} --enable-static=yes --enable-shared=no --with-pic && echo $? \
    && make -j 6 \
    && make install \
    && cd ../ && rm -rf apr-${APR_VERSION} && rm -rf apr-${APR_VERSION}.tar.gz

# install libexpat
RUN mkdir -p dependencies/expat/${EXPAT_VERSION} \
    && wget https://github.com/libexpat/libexpat/releases/download/${EXPAT_RVERSION}/expat-${EXPAT_VERSION}.tar.gz --no-check-certificate \
    && tar -xf expat-${EXPAT_VERSION}.tar.gz \
    && cd expat-${EXPAT_VERSION} \
    && ./configure --prefix=/dependencies/expat/${EXPAT_VERSION} --enable-static=yes --enable-shared=no --with-pic && echo $? \
    && make -j 6 \
    && make install \
    && cd ../ && rm -rf expat-${EXPAT_VERSION} && rm -rf expat-${EXPAT_VERSION}.tar.gz

# install Apr-util
RUN mkdir -p dependencies/apr-util/${APRUTIL_VERSION} \
    && wget https://archive.apache.org/dist/apr/apr-util-${APRUTIL_VERSION}.tar.gz --no-check-certificate \
    && tar -xf apr-util-${APRUTIL_VERSION}.tar.gz \
    && cd apr-util-${APRUTIL_VERSION} \
    && ./configure --prefix=/dependencies/apr-util/${APRUTIL_VERSION} --enable-static=yes --enable-shared=no --with-pic --with-apr=/dependencies/apr/1.7.0 --with-expat=/dependencies/expat/2.3.0 && echo $? \
    && make -j 6 \
    && make install \
    && cd ../ && rm -rf apr-util-${APRUTIL_VERSION} && rm -rf apr-util-${APRUTIL_VERSION}.tar.gz

# install googletest
RUN mkdir -p dependencies/googletest/${GTEST_VERSION}/ \
    && wget https://github.com/google/googletest/archive/refs/tags/release-${GTEST_VERSION}.tar.gz --no-check-certificate \
    && tar -xf release-${GTEST_VERSION}.tar.gz \
    && cd googletest-release-${GTEST_VERSION}/  \
    && mkdir build && cd build \
    && cmake .. -DCMAKE_INSTALL_PREFIX=/dependencies/googletest/${GTEST_VERSION}/ \
    && make \
    && make install \
    && cd ../.. && rm -rf release-${GTEST_VERSION}.tar.gz && rm -rf googletest-release-${GTEST_VERSION}/

#install log4cxx
RUN mkdir -p dependencies/apache-log4cxx/${LOG4CXX_VERSION} \
    && wget https://archive.apache.org/dist/logging/log4cxx/${LOG4CXX_VERSION}/apache-log4cxx-${LOG4CXX_VERSION}.tar.gz --no-check-certificate \
    && tar -xf apache-log4cxx-${LOG4CXX_VERSION}.tar.gz \
    && cd apache-log4cxx-${LOG4CXX_VERSION} \
    && autoreconf -f -i \
    && ./configure --prefix=/dependencies/apache-log4cxx/${LOG4CXX_VERSION}/ --enable-static=yes --enable-shared=no --with-pic --with-apr=/dependencies/apr/1.7.0/ --with-apr-util=/dependencies/apr-util/1.6.1/ && echo $? \
    && make -j 6 ; echo 0 \
    && automake --add-missing \
    && make install \
    && cd .. && rm -rf apache-log4cxx-${LOG4CXX_VERSION}.tar.gz && rm -rf apache-log4cxx-${LOG4CXX_VERSION}

#Installing Apache and apr source code
RUN cd /; mkdir build-dependencies \
    && wget --no-check-certificate https://archive.apache.org/dist/apr/apr-${APR_VERSION}.tar.gz \
    && tar -xf apr-${APR_VERSION}.tar.gz \
    && mv -f apr-${APR_VERSION} build-dependencies \
    && wget --no-check-certificate https://archive.apache.org/dist/apr/apr-util-${APRUTIL_VERSION}.tar.gz \
    && tar -xf apr-util-${APRUTIL_VERSION}.tar.gz \
    && mv -f apr-util-${APRUTIL_VERSION} build-dependencies \
    && wget --no-check-certificate http://archive.apache.org/dist/httpd/httpd-2.2.31.tar.gz \
    && tar -xf httpd-2.2.31.tar.gz \
    && mv -f httpd-2.2.31 build-dependencies \
    && wget --no-check-certificate http://archive.apache.org/dist/httpd/httpd-2.4.23.tar.gz \
    && tar -xf httpd-2.4.23.tar.gz \
    && mv -f httpd-2.4.23 build-dependencies

RUN rm -rf apr-util-${APRUTIL_VERSION} && rm -rf apr-util-${APRUTIL_VERSION}.tar.gz \
    && rm -rf httpd-2.4.23.tar.gz && rm -rf httpd-2.2.31.tar.gz \
    && rm -rf grpc \
    && rm -rf apr-${APR_VERSION} && rm -rf apr-${APR_VERSION}.tar.gz

RUN apt-get install libpcre3 libpcre3-dev -y
RUN apt-get install apache2 -y && a2enmod proxy && a2enmod proxy_http \
    && a2enmod proxy_balancer && a2enmod dav

#Build and install boost
RUN wget https://boostorg.jfrog.io/artifactory/main/release/${BOOST_VERSION}/source/${BOOST_FILENAME}.tar.gz \
    && tar -xvf ${BOOST_FILENAME}.tar.gz \
    && cd ${BOOST_FILENAME} \
    && ./bootstrap.sh --with-libraries=filesystem,system --prefix=/dependencies/boost/${BOOST_VERSION}/ \
    && ./b2 install define=BOOST_ERROR_CODE_HEADER_ONLY link=static threading=multi cxxflags="-fvisibility=hidden -fPIC" cflags="-fvisibility=hidden -fPIC" \
    && cd .. && rm -rf ${BOOST_FILENAME} && rm ${BOOST_FILENAME}.tar.gz

# install pcre
RUN mkdir -p dependencies/pcre/${PCRE_VERSION}/ \
    && wget https://ftp.exim.org/pub/pcre/pcre-${PCRE_VERSION}.tar.gz --no-check-certificate \
    && tar -xvf pcre-${PCRE_VERSION}.tar.gz \
    && cd pcre-${PCRE_VERSION} \
    && ./configure --prefix=/dependencies/pcre/${PCRE_VERSION} --enable-jit \
    && make && make install \
    && cd .. && rm -rf ${PCRE_VERSION}.tar.gz && rm -rf pcre-${PCRE_VERSION}

# install nginx
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar -xvf nginx-${NGINX_VERSION}.tar.gz -C /build-dependencies \
    && rm -rf nginx-${NGINX_VERSION}.tar.gz

# Install GRPC
RUN cd /; mkdir -p /dependencies/grpc/lib \
  && mkdir -p /dependencies/grpc/include \
  && git clone --shallow-submodules --depth 1 --recurse-submodules -b v${GRPC_VERSION} \
  https://github.com/grpc/grpc \
  && cd grpc \
  && mkdir -p cmake/build \
  && cd cmake/build \
  && cmake \
    -DgRPC_INSTALL=ON \
    -DgRPC_BUILD_TESTS=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DgRPC_BUILD_GRPC_NODE_PLUGIN=OFF \
    -DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN=OFF \
    -DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF \
    -DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF \
    -DgRPC_BUILD_GRPC_PYTHON_PLUGIN=OFF \
    -DCMAKE_CXX_STANDARD=17 \
    -DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF \
    ../.. \
  && make -j2 \
  && make install

# install opentelemetry
RUN cd /; mkdir -p /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/lib \
    && mkdir -p /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/include \
    && git clone https://github.com/open-telemetry/opentelemetry-cpp \
    && cd opentelemetry-cpp/ \
    && git checkout tags/v${OPENTELEMETRY_VERSION} -b v${OPENTELEMETRY_VERSION} \
    && git submodule update --init --recursive \
    && mkdir build \
    && cd build \
    && cmake \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -DBUILD_TESTING=OFF \
      -DWITH_EXAMPLES=OFF \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DWITH_ABSEIL=OFF \
      -DWITH_STL=OFF \
      -DWITH_OTLP=ON \
      -DWITH_OTLP_GRPC=ON \
      -DWITH_OTLP_HTTP=OFF \
      -DCMAKE_CXX_STANDARD=17 \
      -DCMAKE_INSTALL_PREFIX=/dependencies/opentelemetry/${OPENTELEMETRY_VERSION} \
      .. \
    && cmake --build . --target all \
    && cd .. \
    && find . -name "*.so" -type f -exec cp {} /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/lib/ \; \
    && cp build/libopentelemetry_proto.a /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/lib \
    && cp -r api/include/ /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/ \
    && for dir in exporters/*; do if [ -d "$dir" ]; then cp -rf "$dir/include" /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/; fi; done \
    && cp -r sdk/include/ /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/ \
    && cp -r build/generated/third_party/opentelemetry-proto/opentelemetry/proto/ /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/include/opentelemetry/

# Build Webserver Module
COPY . /otel-webserver-module

# --with-pcre-jit","--with-stream","--with-stream_ssl_module","--with-stream_ssl_preread_module","--with-http_v2_module","--without-mail_pop3_module","--without-mail_imap_module","--without-mail_smtp_module","--with-http_stub_status_module","--with-http_realip_module","--with-http_addition_module","--with-http_auth_request_module","--with-http_secure_link_module","--with-http_random_index_module","--with-http_gzip_static_module","--with-http_sub_module","--with-http_dav_module","--with-http_flv_module","--with-http_mp4_module","--with-http_gunzip_module","--with-threads","--with-stream","--with-http_ssl_module
RUN cp -r /dependencies /otel-webserver-module/ \
    && cp -r /build-dependencies /otel-webserver-module/ \
    && cd /otel-webserver-module \
    && ./gradlew assembleWebServerModule -DtargetSystem=debian
