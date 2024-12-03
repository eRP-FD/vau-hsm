# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

FROM conanio/gcc9:1.43.0 AS prerequisites

USER root
ARG NEXUS_USERNAME
ARG NEXUS_PASSWORD
ARG NEXUS_SRV=nexus.epa-dev.net/repository/
ARG NEXUS_TI_PATH=erp-contrib/ti_compiler_suites/
ARG NEXUS_TI_PKG=ti_cgt_c6000_7.4.24_linux_installer_x86.bin
ARG RELEASE_VERSION
ARG GITHUB_USERNAME
ARG GITHUB_OAUTH_TOKEN
ENV GITHUB_USERNAME=${GITHUB_USERNAME:-''}
ENV GITHUB_OAUTH_TOKEN=${GITHUB_OAUTH_TOKEN:-''}

# install prerequisites
#
RUN DEBIAN_FRONTEND=noninteractive                             \
    apt-get update -y &&                                       \
    apt-get install -y --no-install-recommends                 \
                                               ca-certificates \
                                               gcc-multilib    \
                                               openssh-client  \
                                               curl            \
                                               git             \
                                               openssh-client  \
                                               libc6-i386      \
                                               lib32stdc++6    \
                                               lib32gcc1       \
                                               lib32z1         \
                                               xutils-dev      \
    &&                                                         \
    apt-get clean all &&                                       \
    apt-get autoclean -y &&                                    \
    apt-get autoremove -y &&                                   \
    rm -rf /var/lib/apt/*                                      \
           /var/cache/apt/*

# due to conan base image based off of Ubuntu 19, ca-certificates contains an old Let's Encrypt CA
#
RUN sed -i '/^mozilla\/DST_Root_CA_X3.crt$/ s/^/!/' /etc/ca-certificates.conf
RUN update-ca-certificates

# use HTTPS checkout due to issues with SSH key formatting when passed through as a build arg
#
RUN git config --global                                                                                 \
               url.https://${GITHUB_USERNAME:-}:${GITHUB_OAUTH_TOKEN:-}@github.ibmgcloud.net/.insteadOf \
               git@github.ibmgcloud.net:

# download TI toolchain
#
RUN curl -fSsL -u ${NEXUS_USERNAME}:${NEXUS_PASSWORD}        \
         https://${NEXUS_SRV}${NEXUS_TI_PATH}${NEXUS_TI_PKG} \
         -o /opt/ti.bin

# install TI toolchain
#
RUN chmod +x /opt/ti.bin &&                    \
    cd /opt &&                                 \
    /opt/ti.bin --mode unattended              \
                --unattendedmodeui none        \
                --installdir /opt/c6000_7.4.24 \
                --debugtrace debug.log

# setup Conan and add the Nexus Conan repository
#
RUN conan config init --force &&                                                    \
    conan profile new default --detect --force &&                                   \
    conan profile update settings.build_type=Release default &&                     \
    conan profile update settings.compiler.libcxx=libstdc++11 default &&            \
    conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal && \
    conan user $NEXUS_USERNAME -r erp -p $NEXUS_PASSWORD

########################################################################################################################

FROM prerequisites as build

# bring the sources
#
WORKDIR /source
COPY . .

# configure & build
#
WORKDIR /build
RUN cmake -S /source -DCMAKE_BUILD_TYPE=Release
RUN cmake --build .

# clean up
#
RUN rm -rf $HOME/.conan     \
           $HOME/.gitconfig \
           $HOME/.local     \
           $HOME/.ssh       \
           /source

########################################################################################################################

FROM prerequisites as tibuild

ARG NEXUS_USERNAME
ARG NEXUS_PASSWORD
ARG NEXUS_SRV=nexus.epa-dev.net/repository/
ARG NEXUS_RELEASE_PATH=erp-raw-releases/com/ibm/erp/hwmake50/
ARG RELEASE_VERSION
ARG NEXUS_RELEASE_PKG=erp-${RELEASE_VERSION}
ARG CFG=rel50
ARG RU_ERP_MDL_VERSION
ARG PU_ERP_MDL_VERSION
# download cryptoserversdk
#
WORKDIR /opt
RUN git clone git@github.ibmgcloud.net:eRp/cryptoserversdk.git && \
    chmod +x /opt/cryptoserversdk/bin/admin/Linux-x86_64/csadm

# bring the sources
#
WORKDIR /firmware
COPY . .
RUN ln -s HWMake hwmake

# configure & build
#
WORKDIR /firmware/HWMake
RUN cp makefile_ti_docker makefile && \
    cp make_ti_docker.sh make.sh && \
    ./make_clean.sh

#patch make.sh with proper versions from git tag for RU artifact
RUN echo "BLOB_DOMAIN=REFZ" > .env && \
    echo "CFG=${CFG}" >> .env && \
    echo "ERP_MDL_VERSION=${RU_ERP_MDL_VERSION}" >> .env
RUN cat ./make.sh
RUN ./make.sh

# upload unsigned artefacts
#
RUN curl -v -u ${NEXUS_USERNAME}:${NEXUS_PASSWORD} \
         --upload-file ../HWMake50/ERP.out         \
         https://${NEXUS_SRV}${NEXUS_RELEASE_PATH}${NEXUS_RELEASE_PKG}-ru.out

# perform testing signing
#
RUN /opt/cryptoserversdk/bin/admin/Linux-x86_64/csadm Model=cs5                                       \
                                                      MMCSignKey=IBM_eRP_RU_RSAAltMdlSig.key#password \
                                                      MakeMTC=../HWMake50/ERP.out

# upload signed test artefacts
#
RUN curl -v -u ${NEXUS_USERNAME}:${NEXUS_PASSWORD} \
         --upload-file ../HWMake50/ERP.mtc         \
         https://${NEXUS_SRV}${NEXUS_RELEASE_PATH}${NEXUS_RELEASE_PKG}-ru.mtc

# PU build
RUN cp make_ti_docker.sh make.sh && \
    ./make_clean.sh
RUN echo "BLOB_DOMAIN=PROD" > .env && \
    echo "CFG=${CFG}" >> .env && \
    echo "ERP_MDL_VERSION=${PU_ERP_MDL_VERSION}" >> .env
RUN ./make.sh
RUN curl -v -u ${NEXUS_USERNAME}:${NEXUS_PASSWORD} \
         --upload-file ../HWMake50/ERP.out         \
         https://${NEXUS_SRV}${NEXUS_RELEASE_PATH}${NEXUS_RELEASE_PKG}-pu.out

# clean up
#
RUN rm -rf $HOME/.conan     \
           $HOME/.gitconfig \
           $HOME/.local     \
           $HOME/.ssh

########################################################################################################################

FROM ubuntu:20.04 AS run

# install dependencies
#
RUN DEBIAN_FRONTEND=noninteractive                          \
    apt-get update -y &&                                    \
    apt-get install -y --no-install-recommends gcc-multilib \
    &&                                                      \
    rm -rf /var/cache/apt/*                                 \
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
