def label = "worker-${UUID.randomUUID().toString()}"

podTemplate(label: label,
    containers: [
        containerTemplate(name: 'maven', image: 'maven', command: 'cat', ttyEnabled: true),
        containerTemplate(name: 'docker', image: 'docker', command: 'cat', ttyEnabled: true),
        containerTemplate(name: 'kubectl', image: 'lachlanevenson/k8s-kubectl:v1.8.8', command: 'cat', ttyEnabled: true),
    ],
    volumes: [
        hostPathVolume(mountPath: '/var/run/docker.sock', hostPath: '/var/run/docker.sock'),
        persistentVolumeClaim(claimName: 'jenkins-m2-agent-repo', mountPath: '/root/.m2')
    ]
)
{
  node(label) {
    stage('Build') {
      container('maven') {
        sh "### Build Environment: ###"
        sh "uname -a"
        sh "java -version"
        sh "mvn -v"

        checkout scm

        sh "mvn -Pdistribution -DskipTests clean install"
      }
    }
    stage('Test') {
      container('docker') {
        sh "### Docker Environment: ###"
        sh "docker info"

        sh "docker images"
      }
    }
    stage('Deploy') {
      container('kubectl') {
        sh "### Kubernetes Environment: ###"
        sh "kubectl cluster-info"

        input 'Do you want to deploy ?'
      }
    }
  }
}