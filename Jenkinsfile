def label = "worker-${UUID.randomUUID().toString()}"

podTemplate(label: label, containers: [
  containerTemplate(name: 'maven', image: 'maven', command: 'cat', ttyEnabled: true),
  containerTemplate(name: 'docker', image: 'docker', command: 'cat', ttyEnabled: true),
  containerTemplate(name: 'kubectl', image: 'lachlanevenson/k8s-kubectl:v1.8.8', command: 'cat', ttyEnabled: true),
],
volumes: [
  hostPathVolume(mountPath: '/var/run/docker.sock', hostPath: '/var/run/docker.sock')
]) {
  node(label) {
    stage('Test') {
      try {
        container('maven') {
          sh "mvn -v"
        }
      }
      catch (exc) {
        println "Failed to test - ${currentBuild.fullDisplayName}"
        throw(exc)
      }
    }
    stage('Build') {
      container('maven') {
        sh "mvn -Pdistribution -DskipTests clean install"
      }
    }
    stage('Create Docker images') {
      container('docker') {
        sh "echo 'Build docker'"
      }
    }
    stage('Run kubectl') {
      container('kubectl') {
        sh "echo 'Run kubectl'"
      }
    }
  }
}