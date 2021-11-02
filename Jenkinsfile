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
                }
            }
            steps {
                gradleCreateRelease()
            }
        }
        
        stage('Check Container Build') {
            when {
                not {
                    branch 'master'
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
                }
            }
            steps {
                loadNexusConfiguration {
	                withCredentials(
	                    [usernamePassword(credentialsId: "jenkins-github-erp", usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
	                ){                   
	                    buildAndPushContainer(
	                    	DOCKER_OPTS:"--build-arg NEXUS_USERNAME='${env.NEXUS_USERNAME}' --build-arg NEXUS_PASSWORD='${env.NEXUS_PASSWORD}' --build-arg GITHUB_USERNAME='${env.GITHUB_USERNAME})' --build-arg GITHUB_OAUTH_TOKEN='${env.GITHUB_OAUTH_TOKEN}'",
	                        DOCKER_BUILDCONTEXT:'firmware',
	                        DOCKER_FILE:'firmware/docker/Dockerfile'
	                    )
	                }
	            }
            }
        }
        
        stage('Publish Release') {
            when {
                anyOf {
                    branch 'master'
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
                }
            }
            steps {
                triggerDeployment('dev')
            }
        }
    }
}
