FROM ubuntu:23.04 as build-env
ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TESTS
ARG SOURCE_COMMIT

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN echo "I am running on ${BUILDPLATFORM}, building for ${TARGETPLATFORM}"

# Prepare whl build env
RUN mkdir -p /usr/local/build

# Build FIX CA
COPY bootstrap /usr/local/sbin/bootstrap
COPY . /usr/src/fixca
RUN apt-get update
RUN apt-get -y install apt-utils
RUN apt-get -y dist-upgrade
RUN apt-get -y install \
        openssl \
        ca-certificates \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-build \
        python3-wheel

WORKDIR /usr/src/fixca
RUN pip wheel --wheel-dir=/usr/local/build --no-cache-dir .
RUN echo "${SOURCE_COMMIT:-unknown}" > /usr/local/etc/git-commit.HEAD


# Setup main image
FROM ubuntu:23.04
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG="en_US.UTF-8"
ENV TERM="xterm-256color"
ENV COLORTERM="truecolor"
ENV EDITOR="vi"
COPY --from=build-env /usr/local /usr/local
ENV PATH=/usr/local/python/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /
RUN groupadd -g "${PGID:-0}" -o fix \
    && useradd -g "${PGID:-0}" -u "${PUID:-0}" -o --create-home fix \
    && apt-get update \
    && apt-get -y --no-install-recommends install apt-utils \
    && apt-get -y dist-upgrade \
    && apt-get -y --no-install-recommends install \
        dumb-init \
        iproute2 \
        dateutils \
        openssl \
        ca-certificates \
        locales \
        python3-minimal \
        python3-pip \
    && ln -s /usr/bin/busybox /usr/local/bin/vi \
    && ln -s /usr/bin/busybox /usr/local/bin/less \
    && echo 'LANG="en_US.UTF-8"' > /etc/default/locale \
    && echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen \
    && locale-gen \
    && pip install --no-cache-dir --break-system-packages /usr/local/build/*.whl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/local/build

ENTRYPOINT ["/bin/dumb-init", "--", "/usr/local/sbin/bootstrap"]
CMD ["/usr/local/bin/fixca"]
