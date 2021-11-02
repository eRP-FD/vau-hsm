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
	                    checkDockerBuild(
	                        DOCKER_OPTS:"--build-arg NEXUS_USERNAME='${env.NEXUS_USERNAME}' --build-arg NEXUS_PASSWORD='${env.NEXUS_PASSWORD}' --build-arg GITHUB_USERNAME='${env.GITHUB_USERNAME})' --build-arg GITHUB_OAUTH_TOKEN='${env.GITHUB_OAUTH_TOKEN}'",
	                        DOCKER_BUILDCONTEXT:'firmware',
	                        DOCKER_FILE:'firmware/docker/Dockerfile'
	                    )
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
                                DOCKER_OPTS:"--build-arg NEXUS_USERNAME='${env.NEXUS_USERNAME}' --build-arg NEXUS_PASSWORD='${env.NEXUS_PASSWORD}' --build-arg GITHUB_USERNAME='${env.GITHUB_USERNAME}' --build-arg GITHUB_OAUTH_TOKEN='${env.GITHUB_OAUTH_TOKEN}' --build-arg RELEASE_VERSION='${releaseVersion}'",
                                DOCKER_BUILDCONTEXT:'firmware',
                                DOCKER_FILE:'firmware/docker/Dockerfile'
                            )
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
