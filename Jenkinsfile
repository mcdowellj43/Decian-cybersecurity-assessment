/* groovylint-disable LineLength */
def majorVersion = ''
def minorVersion = ''
def patchVersion = ''
def buildSkipped = false

pipeline {
    agent {
        label 'ubuntu22-vm'
    }
    options {
        disableConcurrentBuilds(abortPrevious: false)
    }
    environment {
        DOCKER_REGISTRY = 'nexus-registry.decian.net'
        IMAGE_NAME = 'decian-cybersecurity-platform'
    }

    stages {
        stage('Skip?') {
            agent any
            steps {
                script {
                    if (sh(script: "git log -1 --pretty=%B | fgrep -ie '[skip ci]' -e '[ci skip]'", returnStatus: true) == 0) {
                        def isManualTrigger = currentBuild.rawBuild.getCauses()[0].toString().contains('UserIdCause')
                        if (!isManualTrigger) {
                            currentBuild.result = 'SUCCESS'
                            currentBuild.description = 'Build skipped due to commit message'
                            buildSkipped = true
                            return
                        }
                    }
                }
            }
        }

        stage('Checkout') {
            when {
                expression { return !buildSkipped }
            }
            steps {
                checkout scm
            }
        }

        stage('Version Management') {
            when {
                expression { return !buildSkipped }
            }
            steps {
                script {
                    def version = readFile("${env.WORKSPACE}/VERSION").trim()
                    (majorVersion, minorVersion, patchVersion) = version.tokenize('.')

                    // Display version info
                    echo "Current Version: ${majorVersion}.${minorVersion}.${patchVersion}"

                    if (env.BRANCH_NAME == 'master' && !buildSkipped) {
                        // Bump Patch Version, commit
                        patchVersion = patchVersion.toInteger() + 1
                        echo "New Version: ${majorVersion}.${minorVersion}.${patchVersion}"
                        sh "echo ${majorVersion}.${minorVersion}.${patchVersion} > VERSION"
                    }
                    currentBuild.displayName = "# ${majorVersion}.${minorVersion}.${patchVersion}.${env.BUILD_NUMBER} | ${BRANCH_NAME}"
                }
            }
        }

        stage('Lint & Test') {
            when {
                expression { return !buildSkipped }
            }
            parallel {
                stage('Backend Lint & Test') {
                    steps {
                        script {
                            sh """
                                cd backend
                                npm ci
                                npm run lint
                                npm run typecheck
                                npm run test
                            """
                        }
                    }
                }
                stage('Frontend Lint & Test') {
                    steps {
                        script {
                            sh """
                                cd frontend
                                npm ci
                                npm run lint
                                npm run typecheck
                                npm run test
                            """
                        }
                    }
                }
                stage('Go Agent Test') {
                    steps {
                        script {
                            sh """
                                cd agents
                                go mod download
                                go test ./...
                                go vet ./...
                            """
                        }
                    }
                }
            }
        }

        stage('Build & Push Docker Image') {
            when {
                expression { return !buildSkipped }
            }
            steps {
                script {
                    def version = "${majorVersion}.${minorVersion}.${patchVersion}"
                    def dockerTags = [
                        "${version}-${env.BRANCH_NAME.replaceAll("/", "-")}-${env.BUILD_NUMBER}",
                        "${version}-${env.BRANCH_NAME.replaceAll("/", "-")}"
                    ]

                    if (env.BRANCH_NAME == 'master') {
                        dockerTags.add("${version}")
                        dockerTags.add("${majorVersion}.${minorVersion}")
                        dockerTags.add("${majorVersion}")
                        dockerTags.add("latest")
                    }

                    def dockerBuildCommandTags = dockerTags.collect { tag -> "-t $DOCKER_REGISTRY/$IMAGE_NAME:${tag}" }.join(' ')

                    docker.withRegistry('https://nexus-registry.decian.net', 'nexus-docker-writer-username-password') {
                        sh """
                            docker build --build-arg VERSION=$version --push $dockerBuildCommandTags .
                        """
                    }

                    // Display built tags
                    echo "Built and pushed Docker image with tags:"
                    dockerTags.each { tag ->
                        echo "  - $DOCKER_REGISTRY/$IMAGE_NAME:${tag}"
                    }
                }
            }
        }

        stage('Security Scan') {
            when {
                expression { return !buildSkipped }
            }
            steps {
                script {
                    def version = "${majorVersion}.${minorVersion}.${patchVersion}"
                    def imageTag = env.BRANCH_NAME == 'master' ? version : "${version}-${env.BRANCH_NAME.replaceAll("/", "-")}"

                    echo "Running security scan on $DOCKER_REGISTRY/$IMAGE_NAME:${imageTag}"

                    // Add your preferred security scanning tool here
                    // Example with Trivy:
                    sh """
                        echo "Security scanning would run here for image: $DOCKER_REGISTRY/$IMAGE_NAME:${imageTag}"
                        # trivy image --exit-code 1 --severity HIGH,CRITICAL $DOCKER_REGISTRY/$IMAGE_NAME:${imageTag}
                    """
                }
            }
        }

        stage('Deploy to Staging') {
            when {
                allOf {
                    expression { return !buildSkipped }
                    branch 'staging'
                }
            }
            steps {
                script {
                    def version = "${majorVersion}.${minorVersion}.${patchVersion}"
                    def imageTag = "${version}-staging"

                    echo "Deploying to staging environment..."
                    echo "Image: $DOCKER_REGISTRY/$IMAGE_NAME:${imageTag}"

                    // Add your Kubernetes/deployment commands here
                    sh """
                        echo "kubectl set image deployment/decian-platform decian-platform=$DOCKER_REGISTRY/$IMAGE_NAME:${imageTag} -n staging"
                        echo "kubectl rollout status deployment/decian-platform -n staging"
                    """
                }
            }
        }

        stage('Deploy to Production') {
            when {
                allOf {
                    expression { return !buildSkipped }
                    branch 'master'
                }
            }
            steps {
                script {
                    def version = "${majorVersion}.${minorVersion}.${patchVersion}"

                    // Manual approval for production deployments
                    input message: "Deploy version ${version} to production?", ok: 'Deploy'

                    echo "Deploying to production environment..."
                    echo "Image: $DOCKER_REGISTRY/$IMAGE_NAME:${version}"

                    // Add your Kubernetes/deployment commands here
                    sh """
                        echo "kubectl set image deployment/decian-platform decian-platform=$DOCKER_REGISTRY/$IMAGE_NAME:${version} -n production"
                        echo "kubectl rollout status deployment/decian-platform -n production"
                    """
                }
            }
        }

        stage('Re-Commit Version Management') {
            when {
                allOf {
                    expression { return !buildSkipped }
                    branch 'master'
                }
            }
            steps {
                script {
                    sh "git add VERSION"
                    sh "git commit -m '[skip ci] Update VERSION to ${majorVersion}.${minorVersion}.${patchVersion}'"
                    withCredentials([sshUserPrivateKey(credentialsId: 'jenkins-github-ssh-key', keyFileVariable: 'SSH_KEY')]) {
                        sh """
                            GIT_SSH_COMMAND='ssh -i \$SSH_KEY' git push ${scm.userRemoteConfigs[0].url.replace('https://github.com/', 'git@github.com:')} HEAD:master
                        """
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                // Clean up Docker images to save space
                sh """
                    docker image prune -f
                    docker system prune -f --volumes
                """
            }
        }
        success {
            echo "✅ Pipeline completed successfully!"
        }
        failure {
            echo "❌ Pipeline failed!"
            // Add notification logic here (Slack, email, etc.)
        }
    }
}