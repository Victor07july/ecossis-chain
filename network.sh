#!/bin/bash
# https://www.shellscript.sh/variables2.html


function createCluster() {
cat << EOF > resources/kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.30.2
  extraPortMappings:
  - containerPort: 30949
    hostPort: 80
  - containerPort: 30950
    hostPort: 443
EOF

kind create cluster --config=./resources/kind-config.yaml

  export STORAGE_CLASS=standard
  export DATABASE=couchdb

  echo "Aguardando por 5 segundos..."
  sleep 5
  echo "Prosseguindo."

  # kubectl create namespace istio-system

  istioctl operator init
  # altere o type: NodePort para LoadBalancer

  sleep 5

  kubectl apply -f - <<EOF
  apiVersion: install.istio.io/v1alpha1
  kind: IstioOperator
  metadata:
    name: istio-gateway
    namespace: istio-system
  spec:
    addonComponents:
      grafana:
        enabled: false
      kiali:
        enabled: false
      prometheus:
        enabled: false
      tracing:
        enabled: false
    components:
      ingressGateways:
        - enabled: true
          k8s:
            hpaSpec:
              minReplicas: 2
            resources:
              limits:
                cpu: 500m
                memory: 512Mi
              requests:
                cpu: 100m
                memory: 128Mi
            service:
              ports:
                - name: http
                  port: 80
                  targetPort: 8080
                  nodePort: 30949
                - name: https
                  port: 443
                  targetPort: 8443
                  nodePort: 30950
              type: NodePort 
          name: istio-ingressgateway
      pilot:
        enabled: true
        k8s:
          hpaSpec:
            minReplicas: 1
          resources:
            limits:
              cpu: 300m
              memory: 512Mi
            requests:
              cpu: 100m
              memory: 128Mi
    meshConfig:
      accessLogFile: /dev/stdout
      enableTracing: false
      outboundTrafficPolicy:
        mode: ALLOW_ANY
    profile: default

EOF

  sleep 5

kubectl apply -f - <<EOF
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: istio-gateway
  namespace: istio-system
spec:
  addonComponents:
    grafana:
      enabled: false
    kiali:
      enabled: false
    prometheus:
      enabled: false
    tracing:
      enabled: false
  components:
    ingressGateways:
      - enabled: true
        k8s:
          hpaSpec:
            minReplicas: 1
          resources:
            limits:
              cpu: 500m
              memory: 512Mi
            requests:
              cpu: 100m
              memory: 128Mi
          service:
            ports:
              - name: http
                port: 80
                targetPort: 8080
                nodePort: 30949
              - name: https
                port: 443
                targetPort: 8443
                nodePort: 30950
            type: NodePort
        name: istio-ingressgateway
    pilot:
      enabled: true
      k8s:
        hpaSpec:
          minReplicas: 1
        resources:
          limits:
            cpu: 300m
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 128Mi
  meshConfig:
    accessLogFile: /dev/stdout
    enableTracing: false
    outboundTrafficPolicy:
      mode: ALLOW_ANY
  profile: default

EOF

  echo "Aguarde 30 segundos"
  sleep 30
  echo "Prosseguindo."

  CLUSTER_IP=$(kubectl -n istio-system get svc istio-ingressgateway -o json | jq -r .spec.clusterIP) # original

kubectl apply -f - <<EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
           lameduck 5s
        }
        rewrite name regex (.*)\.localho\.st istio-ingressgateway.istio-system.svc.cluster.local
        hosts {
          fallthrough
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
           pods insecure
           fallthrough in-addr.arpa ip6.arpa
           ttl 30
        }
        prometheus :9153
        forward . /etc/resolv.conf {
           max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
    }
EOF

  echo "Instalando Operador HLF"

  # tenta instalar o operador mais atualizado, caso a internet permita
  echo "-------------------------------"

  # helm install hlf-operator resources/hlf-operator-1.9.2.tgz

  # helm repo add kfs https://kfsoftware.github.io/hlf-helm-charts --force-update
  helm install hlf-operator --version=1.10.0 -- kfs/hlf-operator
  # helm upgrade --install hlf-operator --version=1.11.1 -- kfs/hlf-operator

  #echo "CASO HAJA ERRO NESSA ÁREA, PODE IGNORAR"
  echo "--------------------------------"

  # instala o plugin hlf ao kubectl
  kubectl krew install hlf

  echo "Aguardo 1 minuto para o carregamento do operador Fabric"
  #sleep 60

  export PEER_IMAGE=hyperledger/fabric-peer
  export PEER_VERSION=3.0.0

  export ORDERER_IMAGE=hyperledger/fabric-orderer
  export ORDERER_VERSION=2.5.5

  export CA_IMAGE=hyperledger/fabric-ca
  export CA_VERSION=1.5.7

  # export ORDERER_IMAGE=hyperledger/fabric-orderer
  # export ORDERER_VERSION=3.0.0

  # export CA_IMAGE=hyperledger/fabric-ca
  # export CA_VERSION=1.5.13

  echo "Criando ca para INMETRO"
  
  kubectl hlf ca create  --image=$CA_IMAGE --version=$CA_VERSION --storage-class=standard --capacity=1Gi --name=inmetro-ca \
      --enroll-id=enroll --enroll-pw=enrollpw --hosts=inmetro-ca.localho.st --istio-port=443 #--output=true #> resources/inmetro-ca.yaml

  kubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all
  sleep 10

  echo "Registrando usuario no CA para os peers"


  # register user in CA for peers
  kubectl hlf ca register --name=inmetro-ca --user=peer --secret=peerpw --type=peer \
  --enroll-id enroll --enroll-secret=enrollpw --mspid INMETROMSP

  echo "Realizando deploy de 1 peer para a organizacao INMETRO"


  export PEER_IMAGE=quay.io/kfsoftware/fabric-peer
  export PEER_VERSION=2.4.1-v0.0.3
  export MSP_ORG=INMETROMSP
  export PEER_SECRET=peerpw

  kubectl hlf peer create --statedb=$DATABASE --image=$PEER_IMAGE --version=$PEER_VERSION --storage-class=$STORAGE_CLASS --enroll-id=peer --mspid=$MSP_ORG \
  --enroll-pw=$PEER_SECRET --capacity=5Gi --name=inmetro-peer0 --ca-name=inmetro-ca.default --k8s-builder=true --hosts=peer0-inmetro.localho.st --istio-port=443


    kubectl wait --timeout=180s --for=condition=Running fabricpeers.hlf.kungfusoftware.es --all
  sleep 10

  # criando orderers
  echo "Criando 1 orderer"

  kubectl hlf ca create  --image=$CA_IMAGE --version=$CA_VERSION --storage-class=$STORAGE_CLASS --capacity=1Gi --name=ord-ca \
      --enroll-id=enroll --enroll-pw=enrollpw --hosts=ord-ca.localho.st --istio-port=443

  kubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all

  kubectl hlf ca register --name=ord-ca --user=orderer --secret=ordererpw \
      --type=orderer --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP --ca-url="https://ord-ca.localho.st:443"


  # admin host = channel participation API

  kubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \
      --storage-class=$STORAGE_CLASS --enroll-id=orderer --mspid=OrdererMSP \
      --enroll-pw=ordererpw --capacity=2Gi --name=ord-node0 --ca-name=ord-ca.default \
      --hosts=orderer0-ord.localho.st --admin-hosts=admin-orderer0-ord.localho.st --istio-port=443

  kubectl wait --timeout=180s --for=condition=Running fabricorderernodes.hlf.kungfusoftware.es --all


  echo "Iniciando processo de levantamento de canal..."
  echo "Registrando identidade das organizacoes..."

  ## register OrdererMSP Identity
  # register
  kubectl hlf ca register --name=ord-ca --user=admin --secret=adminpw \
      --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP


  kubectl hlf identity create --name orderer-admin-sign --namespace default \
      --ca-name ord-ca --ca-namespace default \
      --ca ca --mspid OrdererMSP --enroll-id admin --enroll-secret adminpw # sign identity

  kubectl hlf identity create --name orderer-admin-tls --namespace default \
      --ca-name ord-ca --ca-namespace default \
      --ca tlsca --mspid OrdererMSP --enroll-id admin --enroll-secret adminpw # tls identity

  ## Register INMETRO
  # register
  kubectl hlf ca register --name=inmetro-ca --namespace=default --user=admin --secret=adminpw \
      --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=INMETROMSP

  # enroll
  kubectl hlf identity create --name inmetro-admin --namespace default \
      --ca-name inmetro-ca --ca-namespace default \
      --ca ca --mspid INMETROMSP --enroll-id admin --enroll-secret adminpw


}


function createChannel() {
echo "Criando canal principal"
sleep 10

export PEER_ORG_SIGN_CERT=$(kubectl get fabriccas inmetro-ca -o=jsonpath='{.status.ca_cert}')
export PEER_ORG_TLS_CERT=$(kubectl get fabriccas inmetro-ca -o=jsonpath='{.status.tlsca_cert}')
export IDENT_8=$(printf "%8s" "")
export ORDERER_TLS_CERT=$(kubectl get fabriccas ord-ca -o=jsonpath='{.status.tlsca_cert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node0 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )

kubectl apply -f - <<EOF
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricMainChannel
metadata:
  name: demo
spec:
  name: demo
  adminOrdererOrganizations:
    - mspID: OrdererMSP
  adminPeerOrganizations:
    - mspID: INMETROMSP
  channelConfig:
    application:
      acls: null
      capabilities:
        - V2_0
      policies: null
    capabilities:
      - V2_0
    orderer:
      batchSize:
        absoluteMaxBytes: 1048576
        maxMessageCount: 10
        preferredMaxBytes: 524288
      batchTimeout: 2s
      capabilities:
        - V2_0
      etcdRaft:
        options:
          electionTick: 10
          heartbeatTick: 1
          maxInflightBlocks: 5
          snapshotIntervalSize: 16777216
          tickInterval: 500ms
      ordererType: etcdraft
      policies: null
      state: STATE_NORMAL
    policies: null
  externalOrdererOrganizations: []
  peerOrganizations:
    - mspID: INMETROMSP
      caName: "inmetro-ca"
      caNamespace: "default"
  identities:
    OrdererMSP:
      secretKey: user.yaml
      secretName: orderer-admin-tls
      secretNamespace: default
    OrdererMSP-sign:
      secretKey: user.yaml
      secretName: orderer-admin-sign
      secretNamespace: default
    INMETROMSP:
      secretKey: user.yaml
      secretName: inmetro-admin
      secretNamespace: default
  externalPeerOrganizations: []
  ordererOrganizations:
    - caName: "ord-ca"
      caNamespace: "default"
      externalOrderersToJoin:
        - host: ord-node0
          port: 7053
      mspID: OrdererMSP
      ordererEndpoints:
        - orderer0-ord.localho.st:443
      orderersToJoin: []
  orderers:
    - host: orderer0-ord.localho.st
      port: 443
      tlsCert: |-
${ORDERER0_TLS_CERT}
EOF

echo "Aguardando 10 segundos para o canal ser carregado"
sleep 10
echo "Ingressando peers da organizaçao INMETRO no canal"


export IDENT_8=$(printf "%8s" "")
export ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node0 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )

kubectl apply -f - <<EOF
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricFollowerChannel
metadata:
  name: demo-inmetromsp
spec:
  anchorPeers:
    - host: inmetro-peer0.default
      port: 7051
  hlfIdentity:
    secretKey: user.yaml
    secretName: inmetro-admin
    secretNamespace: default
  mspId: INMETROMSP
  name: demo
  externalPeersToJoin: []
  orderers:
    - certificate: |
${ORDERER0_TLS_CERT}
      url: grpcs://ord-node0.default:7050
  peersToJoin:
    - name: inmetro-peer0
      namespace: default
EOF

  echo "Fim"
  echo "Aguarde 10 segundos para o canal ser carregado"
  sleep 10

}


function setOperator() {
    API_URL=api-operator.localho.st # URL de acesso
    kubectl hlf operatorapi create --name=operator-api --namespace=default --hosts=$API_URL --ingress-class-name=istio

    echo "Aguardando 30 segundos para a API ser carregada"
    sleep 30

    HOST=operator-ui.localho.st
    API_URL="http://api-operator.localho.st/graphql"
    kubectl hlf operatorui create --name=operator-ui --namespace=default --hosts=$HOST --ingress-class-name=istio --api-url=$API_URL

    echo "Aguardando 30 segundos para o Operator UI ser carregado"
    sleep 30

    echo "Operator UI configurado. Acesse-o pela URL: https://operator-ui.localho.st"

    echo "Em caso de erro, verifique se o firewall está bloqueando o acesso ao Operator UI ou a suas dependências"
}


function installCC() {
  CHAINCODE_LABEL=$1

  kubectl hlf inspect -c=demo --output resources/network.yaml -o INMETROMSP -o OrdererMSP
  kubectl hlf ca register --name=inmetro-ca --user=admin --secret=adminpw --type=admin \
    --enroll-id enroll --enroll-secret=enrollpw --mspid INMETROMSP
  kubectl hlf ca enroll --name=inmetro-ca --user=admin --secret=adminpw --mspid INMETROMSP \
          --ca-name ca  --output resources/peer-inmetro.yaml

  kubectl hlf utils adduser --userPath=resources/peer-inmetro.yaml --config=resources/network.yaml --username=admin --mspid=INMETROMSP


  # calcula id do chaincode  
  export PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=./chaincode/$CHAINCODE_LABEL --language=golang --label=$CHAINCODE_LABEL)
  echo "PACKAGE_ID=$PACKAGE_ID"

  echo "Esse processo pode levar alguns minutos"
  echo "Instalando chaincode na organização INMETRO"

  kubectl hlf chaincode install --path=./chaincode/$CHAINCODE_LABEL \
    --config=resources/network.yaml --language=golang --label=$CHAINCODE_LABEL --user=admin --peer=inmetro-peer0.default

  # esse processo de aguardar evita erros com o approve
  echo "Aguardando 1 minuto para o pod dos chaincodes serem carregado"
  sleep 60

  echo "Aprovando chaincode em ambas as organizações"
  
  #Organização INMETRO
  kubectl hlf chaincode approveformyorg --config=resources/network.yaml --user=admin --peer=inmetro-peer0.default \
      --package-id=$PACKAGE_ID \
      --version "1.0" --sequence 1 --name=$CHAINCODE_LABEL \
      --policy="AND('INMETROMSP.member')" --channel=demo



  echo "Aguarde 10 segundos..."
  sleep 10
  echo "Realizando commit do chaincode"
  
  kubectl hlf chaincode commit --config=resources/network.yaml --mspid=INMETROMSP --user=admin \
    --version "1.0" --sequence 1 --name=$CHAINCODE_LABEL \
    --policy="AND('INMETROMSP.member')" --channel=demo

}


function upgradeCC() {
  CHAINCODE_LABEL=$1
  CHAINCODE_VERSION=$2
  CHAINCODE_SEQUENCE=$3

  kubectl hlf inspect -c=demo --output resources/network.yaml -o INMETROMSP -o OrdererMSP
  kubectl hlf ca register --name=inmetro-ca --user=admin --secret=adminpw --type=admin \
    --enroll-id enroll --enroll-secret=enrollpw --mspid INMETROMSP
  kubectl hlf ca enroll --name=inmetro-ca --user=admin --secret=adminpw --mspid INMETROMSP \
          --ca-name ca  --output resources/peer-inmetro.yaml

  kubectl hlf utils adduser --userPath=resources/peer-inmetro.yaml --config=resources/network.yaml --username=admin --mspid=INMETROMSP

  # calcula id do chaincode    
  export PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=./chaincode/$CHAINCODE_LABEL --language=golang --label=$CHAINCODE_LABEL)
  echo "PACKAGE_ID=$PACKAGE_ID"

  echo "Esse processo pode levar alguns minutos"
  echo "Instalando chaincode na organização INMETRO"

  kubectl hlf chaincode install --path=./chaincode/$CHAINCODE_LABEL \
    --config=resources/network.yaml --language=golang --label=$CHAINCODE_LABEL --user=admin --peer=inmetro-peer0.default

  # esse processo de aguardar evita erros com o approve
  echo "Aguardando 1 minuto para o pod dos chaincodes serem carregado"
  sleep 60

  echo "Aprovando chaincode em ambas as organizações"
  
  #Organização INMETRO
  kubectl hlf chaincode approveformyorg --config=resources/network.yaml --user=admin --peer=inmetro-peer0.default \
      --package-id=$PACKAGE_ID \
      --version $CHAINCODE_VERSION --sequence $CHAINCODE_SEQUENCE --name=$CHAINCODE_LABEL \
      --policy="AND('INMETROMSP.member')" --channel=demo



  echo "Aguarde 10 segundos..."
  sleep 10
  echo "Realizando commit do chaincode"
  
  kubectl hlf chaincode commit --config=resources/network.yaml --mspid=INMETROMSP --user=admin \
    --version $CHAINCODE_VERSION --sequence $CHAINCODE_SEQUENCE --name=$CHAINCODE_LABEL \
    --policy="AND('INMETROMSP.member')" --channel=demo

}

if [ "$1" == "up" ]; then
    echo "Iniciando processo de levantamento da rede"
    createCluster
    createChannel
    echo "Verifique o status dos pods com o comando: 'kubectl get pods'"

elif [ "$1" == "chaincode" ]; then
  echo "Iniciando processo de deploy do chaincode"
  echo "Nome do chaincode: $2"
  installCC $2
  echo "Verifique o status dos pods com o comando: 'kubectl get pods'"

elif [ "$1" == "upgrade" ]; then
  echo "Realizando upgrade do chaincode"
  echo "Nome do chaincode: $2"
  echo "Versão do chaincode: $3"
  echo "Sequência: $4"
  upgradeCC $2 $3 $4

elif [ "$1" == "operator" ]; then
  echo "Levantando o Operator UI"
  setOperator

elif [ "$1" == "down" ]; then
  echo "Iniciando processo de destruicao do cluster Kubernetes"
    
kubectl delete fabricorderernodes.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricpeers.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabriccas.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricchaincode.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricmainchannels --all-namespaces --all
kubectl delete fabricfollowerchannels --all-namespaces --all
kubectl delete fabricnetworkconfigs --all-namespaces --all
kubectl delete fabricidentities --all-namespaces --all
kind delete cluster

  exit 0

elif [ "$1" == "help" ]; then
  echo "Alguns dos comandos que podem ajudar a diagnosticar problemas"
  echo "--------------------"
  echo "Verificar status do canal:"
  echo "--------------------"
  echo "kubectl get fabricmainchannel"
  echo "kubectl get fabricfollowerchannel"
  echo "Em caso de erro, use: "
  echo "kubectl get fabricmainchannel <canal> -o yaml"
  echo "kubectl get fabricfollowerchannel <canal> -o yaml"
  echo "--------------------"
  echo "Verificar status dos pods"
  echo "--------------------"
  echo "kubectl get pods"
  echo "kubectl get pods -o wide"

else
    echo "Comando não reconhecido"
    echo "Comandos possíveis: "
    echo "'up' - Inicia o cluster Kubernetes"
    echo "'chaincode <nome do chaincode>' - Realiza o deploy do chaincode"
    echo "'upgrade' <nome do chaincode> <versao> <sequencia> - Faz o upgrade do chaincode"
    echo "'down' - Destrói o cluster Kubernetes e todos os recursos criados"
    echo "'help' - Mostra alguns comandos que podem ajudar a diagnosticar problemas na rede"
    exit 1
fi