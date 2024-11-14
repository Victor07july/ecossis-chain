# atualizando
sudo apt update && sudo apt upgrade

# kubectl
echo "Instalando o Kubectl"
sudo apt install kubectl
sudo snap install kubectl --classic

# KinD
echo "Instalando o KinD"
# For AMD64 / x86_64
[ $(uname -m) = x86_64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Krew
echo "Instalando o Krew"

(
  set -x; cd "$(mktemp -d)" &&
  OS="$(uname | tr '[:upper:]' '[:lower:]')" &&
  ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')" &&
  KREW="krew-${OS}_${ARCH}" &&
  curl -fsSLO "https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW}.tar.gz" &&
  tar zxvf "${KREW}.tar.gz" &&
  ./"${KREW}" install krew
)

# # para adicionar no PATH
# nova_linha="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"

# # Verifica se a linha já existe no .bashrc
# if grep -Fxq "$nova_linha" ~/.bashrc; then
#     echo "A linha já existe no arquivo .bashrc."
# else
#     # Adiciona a nova linha ao .bashrc
#     echo "$nova_linha" >> ~/.bashrc
#     echo "Linha adicionada ao arquivo .bashrc."

echo 'export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"' >> ~/.bashrc

# Helm
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt update
sudo apt install helm
sudo snap install helm --classic

# JQ
echo "Instalando o JQ"
sudo apt install jq

# Docker
echo "Instalando o Docker"
sudo apt install docker
sudo snap install docker --classic

# Istioctl
echo "Instalando o Istioctl"

curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.23.0 TARGET_ARCH=x86_64 sh -
mv istio-1.23.0/ istioctl
mv istioctl /$HOME
nova_linha="$HOME/istioctl/bin:\$PATH"


# # Verifica se a linha já existe no .bashrc
# if grep -Fxq "$nova_linha" ~/.bashrc; then
#     echo "A linha já existe no arquivo .bashrc."
# else
#     # Adiciona a nova linha ao .bashrc
#     echo "$nova_linha" >> ~/.bashrc
#     echo "Linha adicionada ao arquivo .bashrc."

echo 'export PATH="$HOME/istioctl/bin:$PATH"' >> ~/.bashrc
