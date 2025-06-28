@Library('jenkins-shared-library@main') _

singleImageBuild(
    repo: 'https://github.com/petedillo/dio-sso',
    registry: 'diolab:5000',
    host: 'serverpi',
    sshCreds: 'jenkins-petedillo',
    composePath: '/home/pete/services/dio-sso/compose.yaml',
    imageName: 'dio-sso',
    branch: 'main',
    buildArgs: [:],
    contextPath: '.',
    dockerfile: 'Dockerfile',
    platform: 'linux/arm64',
    push: true
)
