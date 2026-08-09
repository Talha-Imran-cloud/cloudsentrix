// CloudSentrix — Jenkins Pipeline Template
// ==========================================
// Add this as a Jenkinsfile in your repository root.

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Install CloudSentrix') {
            steps {
                sh 'pip install cloudsentrix boto3'
            }
        }

        stage('GCP IAM Scan') {
            steps {
                sh '''
                    cloudsentrix scan \
                        --file sample_data/sample_gcp_iam.json \
                        --cloud gcp \
                        --severity high
                '''
            }
        }

        stage('AWS IAM Scan') {
            steps {
                sh '''
                    cloudsentrix scan \
                        --file sample_data/sample_aws_iam.json \
                        --cloud aws \
                        --severity high
                '''
            }
        }

        stage('Azure RBAC Scan') {
            steps {
                sh '''
                    cloudsentrix scan \
                        --file sample_data/sample_azure_rbac.json \
                        --cloud azure
                '''
            }
        }

        stage('Generate Dashboard') {
            steps {
                sh '''
                    cloudsentrix dashboard \
                        --gcp   sample_data/sample_gcp_iam.json \
                        --aws   sample_data/sample_aws_iam.json \
                        --azure sample_data/sample_azure_rbac.json \
                        --output multi-cloud-dashboard.html

                    cloudsentrix report-multi \
                        --gcp   sample_data/sample_gcp_iam.json \
                        --aws   sample_data/sample_aws_iam.json \
                        --azure sample_data/sample_azure_rbac.json \
                        --output multi-cloud-report.pdf
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.html, *.pdf, *.json', allowEmptyArchive: true
        }
        failure {
            echo 'CRITICAL findings detected — check CloudSentrix report!'
        }
    }
}
