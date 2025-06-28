@Library('jenkins-shared-library@main') _

singleImageBuild(
    repo: 'https://github.com/petedillo/dio-sso',
    registry: 'diolab:5000',
    host: 'serverpi',
    sshCreds: 'jenkins-petedillo',
    composePath: 'docker-compose.yml',  // Changed to relative path
    imageName: 'dio-sso',
    branch: 'main',
    buildArgs: [:],
    contextPath: '.',
    dockerfile: 'Dockerfile',  // Explicitly specify Dockerfile
    platform: 'linux/arm64',
    push: true
)
