FROM alpine:3.11.6

ENV http_proxy=http://172.28.224.1:7890
ENV https_proxy=http://172.28.224.1:7890

RUN apk update && apk upgrade
RUN apk add --no-cache         \
    build-base	               \
	curl \
    curl-dev \
    git			               \
	make			           \
	pkgconfig		           \
	protobuf-dev            \
	python			           \
	sudo			           \
	tar			               \
	zip			               \
	unzip			           \
	wget \
    m4 \
    autoconf \
    automake \
    openjdk8-jre \
    libtool \
    linux-headers \
    pcre-dev     \
    cmake

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
ARG NGINX_VERSION="1.22.0"

# Install GRPC
RUN git clone --shallow-submodules --depth 1 --recurse-submodules -b v${GRPC_VERSION} \
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
    -DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF \
    -DCMAKE_CXX_STANDARD=17 \
    ../.. \
  && make -j2 \
  && make install \
  && cd ../../..

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

#install log4cxx
RUN mkdir -p dependencies/apache-log4cxx/${LOG4CXX_VERSION} \
    && wget https://archive.apache.org/dist/logging/log4cxx/${LOG4CXX_VERSION}/apache-log4cxx-${LOG4CXX_VERSION}.tar.gz --no-check-certificate \
    && tar -xf apache-log4cxx-${LOG4CXX_VERSION}.tar.gz \
    && cd apache-log4cxx-${LOG4CXX_VERSION} \
    && ./configure --prefix=/dependencies/apache-log4cxx/${LOG4CXX_VERSION}/ --enable-static=yes --enable-shared=no --with-pic --with-apr=/dependencies/apr/1.7.0/ --with-apr-util=/dependencies/apr-util/1.6.1/ && echo $? \
    && make -j 6 ; echo 0 \
    && automake --add-missing \
    && make install \
    && cd .. && rm -rf apache-log4cxx-${LOG4CXX_VERSION}.tar.gz && rm -rf apache-log4cxx-${LOG4CXX_VERSION}

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

#Installing Apache and apr source code
RUN mkdir build-dependencies \
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

#RUN apt-get install libpcre3 libpcre3-dev -y
#RUN apt-get install apache2 -y && a2enmod proxy && a2enmod proxy_http \
#    && a2enmod proxy_balancer && a2enmod dav

RUN apk add --no-cache pcre-dev

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

# install opentelemetry
RUN mkdir -p dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/lib \
    && mkdir -p dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/include \
    && git clone https://github.com/open-telemetry/opentelemetry-cpp \
    && cd opentelemetry-cpp/ \
    && git checkout tags/v${OPENTELEMETRY_VERSION} -b v${OPENTELEMETRY_VERSION} \
    && git submodule update --init --recursive \
    && mkdir build \
    && cd build \
    && cmake .. -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTING=OFF -DWITH_EXAMPLES=OFF -DBUILD_SHARED_LIBS=ON -DWITH_ABSEIL=OFF -DWITH_STL=OFF -DWITH_OTLP=ON -DWITH_OTLP_GRPC=ON -DWITH_OTLP_HTTP=OFF -DCMAKE_CXX_STANDARD=17 -DCMAKE_INSTALL_PREFIX=/dependencies/opentelemetry/${OPENTELEMETRY_VERSION} \
    && cmake --build . --target all \
    && cd .. \
    && find . -name "*.so" -type f -exec cp {} /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/lib/ \; \
    && cp build/libopentelemetry_proto.a /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/lib \
    && cp -r api/include/ /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/ \
    && for dir in exporters/*; do if [ -d "$dir" ]; then cp -rf "$dir/include" /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/; fi; done \
    && cp -r sdk/include/ /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/ \
    && cp -r build/generated/third_party/opentelemetry-proto/opentelemetry/proto/ /dependencies/opentelemetry/${OPENTELEMETRY_VERSION}/include/opentelemetry/ \
    && cd .. && rm -rf opentelemetry-cpp

ARG NGINX_VERSION="1.22.0"

# install nginx
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar -xvf nginx-${NGINX_VERSION}.tar.gz -C /build-dependencies \
    && rm -rf nginx-${NGINX_VERSION}.tar.gz

# Build Webserver Module
COPY . /otel-webserver-module

RUN cp -r /dependencies /otel-webserver-module/ \
    && cp -r /build-dependencies /otel-webserver-module/ \
    && cd otel-webserver-module \
    && ./gradlew assembleWebServerModule

# COPY libstdc++.so.6.0.28
RUN cd /otel-webserver-module/build/ \
    && tar zxvf opentelemetry-webserver-sdk-x64-linux.tgz \
    && cp /usr/lib/libstdc++.so.6.0.28 opentelemetry-webserver-sdk/sdk_lib/lib/libstdc++.so.6 \
    && mv opentelemetry-webserver-sdk/conf/opentelemetry_sdk_log4cxx.xml.template opentelemetry-webserver-sdk/conf/appdynamics_sdk_log4cxx.xml.template \
    && sed -i 's/opentelemetry_sdk_log4cxx/appdynamics_sdk_log4cxx/' opentelemetry-webserver-sdk/install.sh\
    && rm opentelemetry-webserver-sdk-x64-linux.tgz \
    && tar zcvf opentelemetry-webserver-sdk-x64-linux.tgz opentelemetry-webserver-sdk