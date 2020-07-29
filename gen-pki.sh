# Setup the PKI
mkdir -p pki
cd pki || exit 1

mkdir -p private req crt

echo "Generating private key..."
openssl genrsa -out private/openvpn-access.pem 4096

echo "Generating main request..."
openssl req -nodes -new -key private/openvpn-access.pem -out req/openvpn-access.csr -subj "/C=$1/ST=$2/L=$3/O=$4/OU=$5/CN=$6"

echo "Generating CA public key..."
openssl genrsa -out private/ca.pem 4096

echo "Generating CA request..."
openssl req -nodes -new -x509 -key private/ca.pem -out crt/ca.crt -subj "/CN=OpenVPN-Access Certificate Authority"

echo "Signing vpn request..."
openssl x509 -req -in req/openvpn-access.csr -CA crt/ca.crt -CAkey private/ca.pem -CAcreateserial -out crt/openvpn-access.crt

echo "Generating diphie hellman params..."
openssl dhparam -out dh.pem 4096 &> /dev/null

echo "Generatinng ta secret..."
openvpn --genkey --secret ta.key

