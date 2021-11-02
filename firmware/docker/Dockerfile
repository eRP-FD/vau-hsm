FROM conanio/gcc9:1.35.2 AS prerequisites

########################################################################################################################

USER root

# install prerequisites
#
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update -y && \
    apt-get install -y --no-install-recommends gcc-multilib \
                                               openssh-client && \
    rm -rf /var/cache/apt/* \
           /var/lib/apt/*

# setup Conan and add the Nexus Conan repository
#
RUN conan profile new default --detect && \
    conan profile update settings.build_type=Release default && \
    conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal

# these are the Nexus credentials used by Conan
#
ARG NEXUS_USERNAME
ARG NEXUS_PASSWORD

# log into Conan repository using the Nexus credentials
#
RUN conan user $NEXUS_USERNAME -r erp -p $NEXUS_PASSWORD

# use HTTPS checkout due to issues with SSH key formatting when passed through as a build arg
#
ARG GITHUB_USERNAME
ARG GITHUB_OAUTH_TOKEN
ENV GITHUB_USERNAME=${GITHUB_USERNAME:-''} \
    GITHUB_OAUTH_TOKEN=${GITHUB_OAUTH_TOKEN:-''}
RUN git config --global url.https://${GITHUB_USERNAME:-}:${GITHUB_OAUTH_TOKEN:-}@github.ibmgcloud.net/.insteadOf git@github.ibmgcloud.net:

########################################################################################################################

FROM prerequisites as build

# bring the sources
#
WORKDIR /source
COPY . .

# configure & build
#
WORKDIR /build
RUN cmake -S /source -DCMAKE_BUILD_TYPE=Debug
RUN cmake --build .

# clean up
#
RUN rm -rf $HOME/.conan \
           $HOME/.gitconfig \
           $HOME/.local \
           $HOME/.ssh \
           /source

########################################################################################################################

FROM ubuntu:20.04 AS run

# install dependencies
#
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update -y && \
    apt-get install -y --no-install-recommends gcc-multilib && \
    rm -rf /var/cache/apt/* \
           /var/lib/apt/*

# make a clean run directory
#
WORKDIR /run
RUN rm -rf *
COPY --from=build /build/simulator .

# this is the environment variable that the HSM simulator checks to grab the port it will be listening on
#
ARG simulator_port=3001
ENV SDK_PORT=$simulator_port
EXPOSE $simulator_port

STOPSIGNAL SIGINT

CMD ["/run/bin/bl_sim5", "-h", "-o"]

########################################################################################################################
