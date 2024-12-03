// (C) Copyright IBM Deutschland GmbH 2021, 2024
// (C) Copyright IBM Corp. 2021, 2024
//
// non-exclusively licensed to gematik GmbH

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pipeline {
    agent {
        node {
            label 'master'
        }
    }
    options {
        disableConcurrentBuilds()
        skipDefaultCheckout()
    }
    tools {
        jdk 'jdk_17'
    }
    environment {
        ENABLE_GRADLE_BUILD_CACHE = 'true'
        ENABLE_GRADLE_CONFIG_CACHE = 'true' // gradle 6+
        WARN_GRADLE_CONFIG_CACHE_PROBLEMS = 'true' // do not fail builds for config cache unsupported tasks
    }
    stages {
        stage('Checkout') {
            steps {
                cleanWs()
                commonCheckout()
            }
        }

        stage('Create Release') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                gradleCreateVersionRelease()
            }
        }
        stage('SBOM and Sonar') {
            steps {
                 withVault(
                    [[path: "secret/eRp/dependencytrack", secretValues: [[vaultKey: 'dependencytrack_apikey', envVar: 'DEPENDENCYTRACK_APIKEY']]],
                        [path: "secret/eRp/dependencytrack", secretValues: [[vaultKey: 'frontend_url', envVar: 'DEPENDENCYTRACK_FRONTEND_URL']]],
                        [path: "secret/eRp/dependencytrack", secretValues: [[vaultKey: 'serverhostname', envVar: 'DEPENDENCYTRACK_SERVER_HOSTNAME']]],
                        [path: "secret/eRp/sonarqube", secretValues: [[vaultKey: 'sonarqubetoken', envVar: 'SONARQUBE_TOKEN']]],
                        [path: "secret/eRp/sonarqube", secretValues: [[vaultKey: 'sonarqubeurl', envVar: 'SONARQUBE_URL']]]
                        ]
                    
                 ) {
                    staticAnalysis()
                    dependencyTrack()
                }
            }
        }
        
        stage('SBOM') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                loadNexusConfiguration {
                    withCredentials(
                        [usernamePassword(credentialsId: "jenkins-github-erp", usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
                    ){
                        script {
                            def releaseVersion = sh(returnStdout: true, script: "git describe --tags --match 'v-[0-9\\.]*'").trim()
                            sbomSyft(
                                DOCKER_OPTS:'--build-arg NEXUS_USERNAME="${NEXUS_USERNAME}" --build-arg NEXUS_PASSWORD="${NEXUS_PASSWORD}" --build-arg GITHUB_USERNAME="${GITHUB_USERNAME}" --build-arg GITHUB_OAUTH_TOKEN="${GITHUB_OAUTH_TOKEN}" ' +
                                            "--build-arg RELEASE_VERSION='${releaseVersion}' --build-arg RU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion)}' --build-arg PU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion,true)}' ",
                                DOCKER_BUILDCONTEXT:'firmware',
                                DOCKER_FILE:'firmware/docker/Dockerfile'
                            )
                        }
                    }
                }
            }
        }

        stage('Check Container Build') {
            when {
                not {
                    anyOf {
                        branch 'master'
                        branch 'release/*'
                    }
                }
            }
            steps {
                loadNexusConfiguration {
                    withCredentials(
                        [usernamePassword(credentialsId: "jenkins-github-erp", usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
                    ){
                        script {
                            def releaseVersion = sh(returnStdout: true, script: "git describe --tags --match 'v-[0-9\\.]*'").trim()
                            checkDockerBuild(
                                DOCKER_OPTS:'--build-arg NEXUS_USERNAME="${NEXUS_USERNAME}" --build-arg NEXUS_PASSWORD="${NEXUS_PASSWORD}" --build-arg GITHUB_USERNAME="${GITHUB_USERNAME}" --build-arg GITHUB_OAUTH_TOKEN="${GITHUB_OAUTH_TOKEN}" ' +
                                            "--build-arg RELEASE_VERSION='${releaseVersion}' --build-arg RU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion)}' --build-arg PU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion,true)}' " +
                                            '--target=tibuild',
                                DOCKER_BUILDCONTEXT:'firmware',
                                DOCKER_FILE:'firmware/docker/Dockerfile'
                            )

                            checkDockerBuild(
                                DOCKER_OPTS:'--build-arg NEXUS_USERNAME="${NEXUS_USERNAME}" --build-arg NEXUS_PASSWORD="${NEXUS_PASSWORD}" --build-arg GITHUB_USERNAME="${GITHUB_USERNAME}" --build-arg GITHUB_OAUTH_TOKEN="${GITHUB_OAUTH_TOKEN}" ' +
                                            "--build-arg RELEASE_VERSION='${releaseVersion}' --build-arg RU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion)}' --build-arg PU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion,true)}' ",
                                DOCKER_BUILDCONTEXT:'firmware',
                                DOCKER_FILE:'firmware/docker/Dockerfile'
                            )


                            currentBuild.description = generateDescription (releaseVersion)
                        }
                    }
                }
            }
        }

        stage('Build Container') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                loadNexusConfiguration {
                    withCredentials(
                        [usernamePassword(credentialsId: "jenkins-github-erp", usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
                    ){
                        script {
                            def releaseVersion = sh(returnStdout: true, script: "git describe --tags --match 'v-[0-9\\.]*'").trim()
                            // ti build
                            checkDockerBuild(
                                DOCKER_OPTS:'--build-arg NEXUS_USERNAME="${NEXUS_USERNAME}" --build-arg NEXUS_PASSWORD="${NEXUS_PASSWORD}" --build-arg GITHUB_USERNAME="${GITHUB_USERNAME}" --build-arg GITHUB_OAUTH_TOKEN="${GITHUB_OAUTH_TOKEN}" ' +
                                            "--build-arg RELEASE_VERSION='${releaseVersion}' --build-arg RU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion)}' --build-arg PU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion,true)}' " +
                                            '--target=tibuild',
                                DOCKER_BUILDCONTEXT:'firmware',
                                DOCKER_FILE:'firmware/docker/Dockerfile'
                            )
                            // simulator build
                            buildAndPushContainer(
                                DOCKER_OPTS:'--build-arg NEXUS_USERNAME="${NEXUS_USERNAME}" --build-arg NEXUS_PASSWORD="${NEXUS_PASSWORD}" --build-arg GITHUB_USERNAME="${GITHUB_USERNAME}" --build-arg GITHUB_OAUTH_TOKEN="${GITHUB_OAUTH_TOKEN}" ' +
                                            "--build-arg RELEASE_VERSION='${releaseVersion}' --build-arg RU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion)}' --build-arg PU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion,true)}' ",
                                DOCKER_BUILDCONTEXT:'firmware',
                                DOCKER_FILE:'firmware/docker/Dockerfile'
                            )

                            currentBuild.description = generateDescription (releaseVersion)
                        }
                    }
                }
            }
        }
        stage('HSM Client') {
            agent {
                docker {
                    label 'dockerstage'
                    image 'conanio/gcc9:latest'
                    reuseNode true
                    args '-u root:sudo -v $HOME/tools:$HOME/tools'
                }
            }
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            stages {
                stage ("Publish to Nexus") {
                    steps {
                        script {
                            loadNexusConfiguration {
                                sh '''
                                    conan remote clean &&\
                                    conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal true --force &&\
                                    conan user -r erp -p "${NEXUS_PASSWORD}" "${NEXUS_USERNAME}" &&\
                                    conan export client &&\
                                    conan export client hsmclient/latest@_/_ &&\
                                    conan upload --remote erp --confirm hsmclient
                               '''
                            }
                        }
                    }
                }
            }
        }
        stage('Publish Release') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                finishRelease()
            }
        }

        stage('Deployment to dev') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                script {
                    if (env.BRANCH_NAME == 'master') {
                        triggerDeployment('targetEnvironment': 'dev2')
                    } else if (env.BRANCH_NAME.startsWith('release/1.0.')) {
                        triggerDeployment('targetEnvironment': 'dev')
                    }
                }
            }
        }
    }
    post {
        success {
            script {
                if (env.BRANCH_NAME == 'master' || env.BRANCH_NAME.startsWith("release/")) {
                    slackSendClient(message: "A new version of the eRezept VAU-HSM client is available: ${env.BUILD_DISPLAY_NAME.minus('v-')}. \nFor more information about what this update includes and any requirement for a particular firmware version please visit the 'vau-hsm' repo.",
                                    channel: '#erp-cpp')
                }
            }
        }
    }
}

def getHsmVersion (releaseVersion, isPu = false){
    def releaseSplit = releaseVersion.split('-');
    def versionStr = releaseSplit[1].split("\\.");
    StringBuilder sb = new StringBuilder ();
    sb.append ("0x");
    def b = versionStr[0].toInteger();
    if (isPu){
        def withSignificantBit = (b | 0x00000080);
        sb.append(String.format("%02x", withSignificantBit));
    } else {
        def withSignificantBit = (b & 0x0000007F);
        sb.append(String.format("%02x", withSignificantBit));
    }
    sb.append(String.format("%02x", versionStr[1].toInteger() ));
    sb.append(String.format("%02x", versionStr[2].toInteger() ));
    sb.append(String.format("%02x", (releaseSplit[2].replaceAll("[^0-9]", "").toInteger()) % 256));
    return sb.toString();
}

def generateDescription (releaseVersion) {
    def NEXUS_SRV="nexus.epa-dev.net/repository/";
    def NEXUS_RELEASE_PATH="erp-raw-releases/com/ibm/erp/hwmake50/";
    def NEXUS_RELEASE_PKG="erp-${releaseVersion}";
    def str = "<h5> Artefacts published during this build: </h5>";
    str += "<p>";
    str += """Signed RU mtc: <a href="https://${NEXUS_SRV}${NEXUS_RELEASE_PATH}${NEXUS_RELEASE_PKG}-ru.mtc" target="_blank">${NEXUS_RELEASE_PKG}-ru.mtc</a><br/>""";
    str += """Unsigned RU out: <a href="https://${NEXUS_SRV}${NEXUS_RELEASE_PATH}${NEXUS_RELEASE_PKG}-ru.out" target="_blank">${NEXUS_RELEASE_PKG}-ru.out</a><br/>""";
    str += """Unsigned PU out: <a href="https://${NEXUS_SRV}${NEXUS_RELEASE_PATH}${NEXUS_RELEASE_PKG}-pu.out" target="_blank">${NEXUS_RELEASE_PKG}-pu.out</a><br/>""";
    str += "</p>";
    return str;
}
