<h1 align="center">
    <img width="300" src="https://raw.githubusercontent.com/openvpn-access/authenticator/master/media/vpnms.png" alt="Logo">
</h1>

<h3 align="center">
    Generate Client Certificates
</h3>

<p align="center">
    <a href="https://tightrope.seymour.global/signup_user_complete/?id=io8xcu5aotg65bmjmoe94supwy" target="_blank">
        <img src="https://img.shields.io/badge/Developer%20chat%20on-mattermost-blue" alt="Mattermost Developer Chat">
    </a>
</p>

<br>

### certificate-server

This project is a core component of `openvpn-access`.

### Building the docker image

```Bash
cd certificate-server

# Build the image
sudo docker build -t cert-server -f ./docker/Dockerfile .
```