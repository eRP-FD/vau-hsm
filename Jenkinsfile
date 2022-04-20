// (C) Copyright IBM Deutschland GmbH 2021
// (C) Copyright IBM Corp. 2021
// SPDX-License-Identifier: CC BY-NC-ND 3.0 DE

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
                gradleCreateReleaseEpa()
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
                                DOCKER_OPTS:"--build-arg NEXUS_USERNAME='${env.NEXUS_USERNAME}' --build-arg NEXUS_PASSWORD='${env.NEXUS_PASSWORD}' --build-arg GITHUB_USERNAME='${env.GITHUB_USERNAME})' --build-arg GITHUB_OAUTH_TOKEN='${env.GITHUB_OAUTH_TOKEN}' --build-arg RELEASE_VERSION='${releaseVersion}' --build-arg RU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion)}' --build-arg PU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion,true)}'",
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
                                 
                            buildAndPushContainer(
                                DOCKER_OPTS:"--build-arg NEXUS_USERNAME='${env.NEXUS_USERNAME}' --build-arg NEXUS_PASSWORD='${env.NEXUS_PASSWORD}' --build-arg GITHUB_USERNAME='${env.GITHUB_USERNAME}' --build-arg GITHUB_OAUTH_TOKEN='${env.GITHUB_OAUTH_TOKEN}' --build-arg RELEASE_VERSION='${releaseVersion}' --build-arg RU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion)}' --build-arg PU_ERP_MDL_VERSION='${getHsmVersion(releaseVersion,true)}'",
                                DOCKER_BUILDCONTEXT:'firmware',
                                DOCKER_FILE:'firmware/docker/Dockerfile'
                            )

                            currentBuild.description = generateDescription (releaseVersion)
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
