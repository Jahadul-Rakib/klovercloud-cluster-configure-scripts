#!/bin/sh

aws_access_key=$1
aws_secret_key=$2
aws_region=$3
aws_cluster_name=$4
userEmail=$5
route53_domain=$6
cluster_pass=$7
notificationUrl=$8
companyId=$9
nginx_ip=${10}
istio_ip=${11}
display_name=${12}
istioStatus=${13}
efsPolicyName=${14}
efsSecurityGroupName=${15}
currentAccountId=${16}
loadbalancer_is_exposed=${17}
nginx_loadbalancer_type=${18}
istio_loadbalancer_type=${19}
subnet_id_list=${20}
cluster_id=${21}
efs_service_account_name=${22}
loki_username=${23}
loki_secret=${24}
loki_password=${25}
promithus_username=${26}
promithus_secret=${27}
promithus_password=${28}
console_gateway_url=${29}
token=${30}
clusterType=${31}
private_key_path=${32}
facadeDomain=${33}
listnerDomain=${34}
webappConsoleDomain=${35}
terminalProxyDomain=${36}
temporalHost=${37}
temporalNamespace=${38}
agentOperatorImageVersion=${39}
agentOperatorImageTag=${40}
host_ip=${41}
github_content_root_path=${42}
script_location=${43}

if [ "$clusterType" = "private" ]; then
echo "--------------------starting for private cluster--------------------"
#cd /
command chmod 0600 "$private_key_path"
scp -i "$private_key_path" -o StrictHostKeyChecking=no -r "'$script_location'aws/aws_setup_inside_bastion.sh" ubuntu@"$host_ip":~/aws_setup_inside_bastion.sh
sleep 30
echo "copy files from local to server"

echo "ssh -i "$private_key_path" -o StrictHostKeyChecking=no ubuntu@""$host_ip"""

command ssh -i "$private_key_path" -o StrictHostKeyChecking=no ubuntu@"$host_ip" <<EFO
echo "---------entered into bastion host---------"

command snap install aws-cli --classic

command curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
command sudo mv /tmp/eksctl /usr/local/bin
command eksctl version

command curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.23.6/bin/linux/amd64/kubectl
command sudo chmod +x ./kubectl
command sudo mv ./kubectl /usr/local/bin/kubectl

command aws configure set aws_access_key_id "$aws_access_key"
command aws configure set aws_secret_access_key "$aws_secret_key"
command aws configure set default.region "$aws_region"
command aws eks update-kubeconfig --region "$aws_region" --name "$aws_cluster_name"
command kubectl get node;
echo '---------cluster config update done---------'

command chmod a+x ~/aws_setup_inside_bastion.sh;

#source ~/aws_setup_inside_bastion.sh "$aws_access_key" \
source curl -sSL " + applicationProperties.getGitContentRootUrl() + "/aws_setup_inside_bastion.sh | sh -s -- "$aws_access_key" \
                                   "$aws_secret_key" \
                                   "$aws_region" \
                                   "$aws_cluster_name" \
                                   "$userEmail" \
                                   "$route53_domain" \
                                   "$cluster_pass" \
                                   "$notificationUrl" \
                                   "$companyId" \
                                   "$nginx_ip" \
                                   "$istio_ip" \
                                   "$display_name" \
                                   "$istioStatus" \
                                   "$efsPolicyName" \
                                   "$efsSecurityGroupName" \
                                   "$currentAccountId" \
                                   "$loadbalancer_is_exposed" \
                                   "$nginx_loadbalancer_type" \
                                   "$istio_loadbalancer_type" \
                                   "$subnet_id_list" \
                                   "$cluster_id" \
                                   "$efs_service_account_name" \
                                   "$loki_username" \
                                   "$loki_secret" \
                                   "$loki_password" \
                                   "$promithus_username" \
                                   "$promithus_secret" \
                                   "$promithus_password" \
                                   "$console_gateway_url" \
                                   "$token" \
                                   "$clusterType" \
                                   "$github_content_root_path" \
                                   "$facadeDomain" \
                                   "$listnerDomain" \
                                   "$webappConsoleDomain" \
                                   "$terminalProxyDomain" \
                                   "$temporalHost" \
                                   "$temporalNamespace" \
                                   "$agentOperatorImageVersion" \
                                   "$agentOperatorImageTag"

EFO

else

echo "--------------------starting for public cluster--------------------"

command rm /root/.kube/config
command rm /root/.aws/config /root/.aws/credentials
command aws configure set aws_access_key_id "$aws_access_key"
command aws configure set aws_secret_access_key "$aws_secret_key"
command aws configure set default.region "$aws_region"
echo '---------aws setup done---------'

command aws eks update-kubeconfig --region "$aws_region" --name "$aws_cluster_name"
echo '---------cluster config update done---------'
echo 'progress-step:environment_setup'

echo '---------efs csi driver setup start---------'
sleep 1m
aws iam create-policy --policy-name "$efsPolicyName" \
  --policy-document 'https://raw.githubusercontent.com/kubernetes-sigs/aws-efs-csi-driver/master/docs/iam-policy-example.json'
echo '------------------policy create-----------------'
eksctl utils associate-iam-oidc-provider --region="$aws_region" --cluster "$aws_cluster_name" --approve
wait
echo '------------------oidc policy-----------------'
eksctl create iamserviceaccount \
  --cluster "$aws_cluster_name" \
  --namespace kube-system \
  --name "$efs_service_account_name" \
  --attach-policy-arn arn:aws:iam::"$currentAccountId":policy/"$efsPolicyName" \
  --approve \
  --region "$aws_region" \
  --override-existing-serviceaccounts
wait
sleep 1m
echo '------------------service account-----------------'

command kubectl apply -k "github.com/kubernetes-sigs/aws-efs-csi-driver/deploy/kubernetes/overlays/stable/?ref=release-1.3"
wait
sleep 1m
echo '------------------efs csi driver-----------------'

vpc_id=$(aws eks describe-cluster \
  --name "$aws_cluster_name" \
  --query "cluster.resourcesVpcConfig.vpcId" \
  --output text)
echo '------------------vpc_id-----------------'
wait
cidr_range=$(aws ec2 describe-vpcs \
  --vpc-ids "$vpc_id" \
  --query "Vpcs[].CidrBlock" \
  --output text)
echo '------------------cidr_range-----------------'
wait
security_group_id=$(aws ec2 create-security-group \
  --group-name "$efsSecurityGroupName" \
  --description 'security group for efs' \
  --vpc-id "$vpc_id" \
  --output text)
echo '------------------security_group_id-----------------'
wait
file_system_id=$(aws efs create-file-system \
  --region "$aws_region" \
  --performance-mode generalPurpose \
  --query 'FileSystemId' \
  --output text)
echo "------------------""$file_system_id""-----------------"
wait
aws ec2 authorize-security-group-ingress \
  --group-id "$security_group_id" \
  --protocol tcp \
  --port 2049 \
  --cidr "$cidr_range"
echo '------------------security_group_ingress-----------------'
wait
sleep 2m

for subnetId in $(echo "$subnet_id_list" | grep -o -e "[^,]*"); do
    aws efs create-mount-target \
      --file-system-id "$file_system_id" \
      --subnet-id "$subnetId" \
      --security-groups "$security_group_id"
    wait
    sleep 10
    echo "------------------subnet attach with ""$subnetId""-----------------"
done

echo 'File System Id---------:'"$file_system_id"
sleep 2m
echo '---------efs csi driver setup done---------'

command kubectl apply -f "$github_content_root_path/cert-manager-1.6.1.yaml"
command cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: cluster-letsencrypt
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: support@klovercloud.com
    privateKeySecretRef:
      name: cluster-letsencrypt-key
    solvers:
      - http01:
          ingress:
            class: nginx
EOF
echo '---------cert-manager setup done---------'

command kubectl -n kube-system apply -f "$github_content_root_path/reflector.yaml"
echo '---------reflector setup done---------'

command aws eks delete-addon --cluster-name "$aws_cluster_name" --addon-name aws-ebs-csi-driver --preserve
echo '---------remove default ebs csi driver---------'
command kubectl apply -f "$github_content_root_path/ebs-csi-driver.yaml"
echo '---------new ebs csi driver setup done---------'

sleep 30
command kubectl rollout restart deploy -n kube-system snapshot-controller

command cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: klovercloud
  labels:
    name: klovercloud
EOF

command cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels:
    name: monitoring
EOF
echo "namespace created"

command kubectl apply -f "$github_content_root_path/volume-snapshot-classes.yaml"
command kubectl apply -f "$github_content_root_path/volumesnapshotcontents.yaml"
command kubectl apply -f "$github_content_root_path/volumesnapshots.yaml"
command kubectl apply -f "$github_content_root_path/rbac-snapshot-controller.yaml"
command kubectl apply -f "$github_content_root_path/setup-snapshot-controller.yaml"

command cat <<EOF | kubectl apply -f -
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: eks-sc-efs
provisioner: efs.csi.aws.com
parameters:
  provisioningMode: efs-ap
  fileSystemId: $file_system_id
  directoryPerms: "700"
  gidRangeStart: "1000"
  gidRangeEnd: "2000"
  basePath: "/dynamic_provisioning"
EOF
echo "storage-class eks-sc-efs created"

command cat <<EOF | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: eks-sc-ebs
provisioner: ebs.csi.aws.com
reclaimPolicy: Delete
volumeBindingMode: Immediate
allowVolumeExpansion: true
EOF

command cat <<EOF | kubectl apply -f -
apiVersion: snapshot.storage.k8s.io/v1
deletionPolicy: Delete
driver: ebs.csi.aws.com
kind: VolumeSnapshotClass
metadata:
  name: ebs-snapclass
EOF
echo "storage-class eks-sc-ebs created"

if [ "$nginx_loadbalancer_type" = "CLASSIC" ]; then
  if [ "$loadbalancer_is_exposed" = "true" ]; then
    command kubectl apply -f "$github_content_root_path/ingress-controller-classic.yaml"
  else
    command kubectl apply -f "$github_content_root_path/ingress-controller-classic-internal.yaml"
  fi
else
  if [ "$loadbalancer_is_exposed" = "true" ]; then
    command kubectl apply -f "$github_content_root_path/ingress-controller-nlb.yaml"
  else
    command kubectl apply -f "$github_content_root_path/ingress-controller-nlb-internal.yaml"
  fi
fi

echo '---------nginx-ingress controller setup done---------'

command kubectl delete -A ValidatingWebhookConfiguration ingress-nginx-admission
sleep 1m

command kubectl apply -f "$github_content_root_path/metrics-server.yaml"
command kubectl apply -f "$github_content_root_path/prometheus-node-exporter.yaml" -n monitoring
wait
command cat <<EOF | kubectl apply -f -
apiVersion: v1
data:
  auth: $promithus_secret
kind: Secret
metadata:
  name: basic-auth-secret
  namespace: monitoring
type: Opaque
EOF
wait
echo 'promithus secret created'
sleep 1m

command cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/auth-realm: 'Authentication Required'
    nginx.ingress.kubernetes.io/auth-secret: basic-auth-secret
    nginx.ingress.kubernetes.io/auth-type: basic
  labels:
    app: ingress
  name: prometheus-ingress
  namespace: monitoring
spec:
  rules:
  - host: 'prometheus.$route53_domain'
    http:
      paths:
      - backend:
          service:
            name: monitoring-prometheus-server
            port:
              number: 80
        path: /
        pathType: ImplementationSpecific
EOF
echo 'promithus ingress created'
wait

command kubectl create namespace loki
command kubectl apply -f "$github_content_root_path/loki.yaml"
wait
command cat <<EOF | kubectl apply -f -
apiVersion: v1
data:
  auth: $loki_secret
kind: Secret
metadata:
  name: basic-auth-secret
  namespace: loki
type: Opaque
EOF
wait

command cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/auth-realm: 'Authentication Required '
    nginx.ingress.kubernetes.io/auth-secret: basic-auth-secret
    nginx.ingress.kubernetes.io/auth-type: basic
  labels:
    app: ingress
  name: loki-ingress
  namespace: loki
spec:
  rules:
  - host: 'loki.$route53_domain'
    http:
      paths:
      - backend:
          service:
            name: gateway
            port:
              number: 80
        path: /
        pathType: ImplementationSpecific
EOF
wait

command kubectl create namespace strimzi
command kubectl apply -f "$github_content_root_path/strimzi-operator.yaml" -n strimzi
wait

if [ "$istioStatus" = "true" ]; then
  command kubectl create namespace istio-system
  command kubectl label namespace istio-system role=klovercloud
  command kubectl apply -f "$github_content_root_path/istiod.yaml" -n istio-system
  command kubectl apply -f "$github_content_root_path/istio-discovery.yaml" -n istio-system
  if [ "$istio_loadbalancer_type" = "CLASSIC" ]; then
    if [ "$loadbalancer_is_exposed" = "true" ]; then
      command kubectl apply -f "$github_content_root_path/istio-ingress-classic.yaml"
    else
      command kubectl apply -f "$github_content_root_path/istio-ingress-classic-internal.yaml"
    fi
  else
    if [ "$loadbalancer_is_exposed" = "true" ]; then
      command kubectl apply -f "$github_content_root_path/istio-ingress-nlb.yaml"
    else
      command kubectl apply -f "$github_content_root_path/istio-ingress-nlb-internal.yaml"
    fi
  fi
  command kubectl apply -f "$github_content_root_path/istio-ingress.yaml" -n istio-system
  command kubectl apply -f "$github_content_root_path/istio-egress.yaml" -n istio-system
  command kubectl apply -f "$github_content_root_path/istio-gateway.yaml" -n istio-system
  command cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: default-istio-gateway
  namespace: istio-system
spec:
  selector:
    istio: ingressgateway
  servers:
    - hosts:
        - '*.mesh.$route53_domain'
      port:
        name: http
        number: 80
        protocol: HTTP
EOF
  command kubectl apply -f "$github_content_root_path/kiali.yaml"
  command cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  labels:
    app: ingress
  name: kiali
  namespace: istio-system
spec:
  rules:
  - host: 'kiali.$route53_domain'
    http:
      paths:
      - backend:
          service:
            name: kiali
            port:
              number: 20001
        path: /
        pathType: ImplementationSpecific
EOF
  wait
fi

command helm repo update
sleep 10
echo "-----------------helm update done-----------------"

helm template kc-agent-operator --namespace klovercloud klovercloud-charts/klovercloud-agent-operator --version "$agentOperatorImageVersion" \
    --set operator.image.repository="quay.io/klovercloud/klovercloud-agent-operator" \
    --set operator.image.tag="$agentOperatorImageTag" \
    --set operator.namespace=klovercloud \
    --set platform.user.companyAdmin.password="$cluster_pass" \
    --set platform.user.companyAdmin.email="$userEmail" \
    --set cluster.id="$cluster_id" \
    --set cluster.type="$clusterType" \
    --set cluster.host="AWS" \
    --set cluster.creationType="AUTOMATED" \
    --set cluster.name="$display_name" \
    --set cluster.volumes.storageType="EKS" \
    --set cluster.volumes.storageClass.readWriteMany="eks-sc-efs" \
    --set cluster.volumes.storageClass.readWriteOnce="eks-sc-ebs" \
    --set cluster.volumes.persistentStorage.enabled="true" \
    --set cluster.serviceAccount.name="" \
    --set cluster.psp.enforcePrivilegedPsp="True" \
    --set cluster.volumes.snapshotClass.name=ebs-snapclass \
    --set cluster.volumes.snapshotClassRWM.name=ebs-snapclass \
    --set cluster.notification.webhook.url="$notificationUrl" \
    --set cluster.serviceMesh.istio.enabled="$istioStatus" \
    --set cluster.serviceMesh.istio.gateway.name="default-istio-gateway" \
    --set cluster.nginx.ingressClass.name="" \
    --set platform.namespace=klovercloud \
    --set platform.company.id="$companyId" \
    --set platform.service.domain.wildcard.name="$nginx_ip" \
    --set platform.service.domain.wildcard.tlsSecret="" \
    --set platform.service.domain.ingressClass.name="nginx" \
    --set platform.service.domain.ingressController.type="NGINX" \
    --set platform.service.domain.wildcard.tls.enabled="false" \
    --set platform.service.domain.wildcard.tls.autoSSL="false" \
    --set platform.service.domain.wildcard.tls.certificate.cert="" \
    --set platform.service.domain.wildcard.tls.certificate.key="" \
    --set platform.service.domain.wildcard.tls.certificate.ca="" \
    --set platform.service.domain.wildcard.tls.reflectionEnabled="false" \
    --set platform.application.domain.useServiceDomainConfig="true" \
    --set platform.application.domain.ingressClass.name="" \
    --set platform.application.domain.ingressController.type="" \
    --set platform.application.domain.wildcard.name="" \
    --set platform.application.domain.wildcard.tlsSecret="" \
    --set platform.application.domain.wildcard.tls.enabled="false" \
    --set platform.application.domain.wildcard.tls.autoSSL="false" \
    --set platform.application.domain.wildcard.tls.certificate.cert="" \
    --set platform.application.domain.wildcard.tls.certificate.key="" \
    --set platform.application.domain.wildcard.tls.certificate.ca="" \
    --set platform.application.domain.wildcard.tls.reflectionEnabled="false" \
    --set platform.service.serviceMesh.domain.wildcard.name="mesh.$istio_ip" \
    --set platform.service.serviceMesh.domain.wildcard.tlsSecret="" \
    --set cluster.clusterIssuer.name="cluster-letsencrypt" \
    --set platform.service.terminal.domain="terminal.$nginx_ip" \
    --set platform.service.terminal.proxy.endpoint="https://$terminalProxyDomain/terminal/" \
    --set platform.service.facade.domain="$facadeDomain" \
    --set platform.service.listener.domain="$listnerDomain" \
    --set platform.service.webapp.domain="$webappConsoleDomain" \
    --set platform.service.multiClusterConsoleGateway.domain="$console_gateway_url" \
    --set platform.service.facade.webSocketEndpoint="wss://$facadeDomain/web-socket-ns" \
    --set platform.service.facade.apiAccessToken="$token" \
    --set platform.service.agent.logMode="PRODUCTION" \
    --set platform.resource.allocation.enabled="true" \
    --set platform.resource.allocation.type="MEDIUM" \
    --set temporal.host="$temporalHost" \
    --set temporal.namespace="$temporalNamespace" \
    --set ci.namespace="kcp-tekton-pipelines" \
    --set ci.tekton.enabled="true" \
    --set loki.url="http://loki.$nginx_ip/" \
    --set loki.username="$loki_username" \
    --set loki.password="$loki_password" \
    --set loki.orgId="" \
    --set prometheus.url="http://prometheus.$nginx_ip" \
    --set prometheus.username="$promithus_username" \
    --set prometheus.password="$promithus_password" \
    --set grafana.url="" \
    --set grafana.username="" \
    --set grafana.password="" \
    --set kiali.url="" \
    --set kiali.token="" \
    --set argocd.url="" \
    --set argocd.username="" \
    --set argocd.password="" \
    --set argocd.port="" > klovercloud.yaml
echo "-------------helm file created-------------"
command kubectl apply -f klovercloud.yaml
echo "-------------helm file applied-------------"
wait


sleep 10
command echo nginx-ingress-host-address:$(kubectl get svc -n ingress-nginx ingress-nginx-controller -o=custom-columns=EXTERNAL-IP:.status.loadBalancer.ingress[0].ip)
command echo istio-ingress-host-address:$(kubectl get svc -n istio-system istio-ingressgateway -o=custom-columns=EXTERNAL-IP:.status.loadBalancer.ingress[0].ip)
command echo kiali_token:$(kubectl exec -it -n istio-system deploy/kiali -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
echo 'progress-step:klovercloud_setup'
echo '***--------------------------------DONE--------------------------------***'
fi