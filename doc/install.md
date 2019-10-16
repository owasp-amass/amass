
# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://www.owasp.org/index.php/OWASP_Amass_Project) - Installation Guide

[![Packaging status](https://repology.org/badge/vertical-allrepos/amass.svg)](https://repology.org/metapackage/amass/versions)
[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/amass)
#
# Easy Install in Kali Linux

```bash
sudo apt install amass -y
```


### Snapcraft


```bash
sudo snap install amass
```

Follow these steps to install Snap and Amass + use AppArmor (for autoload) and Add the Snap bin directory to your PATH:

```bash
sudo apt install snapd && sudo systemctl start snapd && sudo systemctl enable snapd && sudo systemctl start apparmor && sudo systemctl enable apparmor && export PATH=$PATH:/snap/bin && snap install go --classic && sudo snap install amass && amass -version
```

Periodically, execute the following command to update all your snap packages:

```bash
sudo snap refresh
```

## Using Docker

1. Build the [Docker](https://docs.docker.com/) image:

```bash
docker build -t amass https://github.com/OWASP/Amass.git
```

2. Run the Docker image:

```bash
docker run -v ~/amass:/amass/ amass enum --list
```

The volume argument allows the Amass graph database to persist between executions and output files to be accessed on the host system.

The wordlists maintained in the Amass git repository are available in `/wordlists/` within the docker container. For example, to use `all.txt`:

```bash
docker run -v ~/amass:/amass/ amass enum -brute -w /wordlists/all.txt -d example.com
```

## Prebuilt Binaries

A [precompiled version is available](https://github.com/OWASP/Amass/releases) with each release.



## If you like Build manually with **Go >= 1.13**

Build your own binary from the latest release of the source code

To build Go Modules, then you can simply execute the following command:

```bash
cd && go get -u github.com/OWASP/Amass/...
```
Build Amass using Go Modules to ensure the proper dependencies, then perform the following steps:

1. Download OWASP Amass:

```bash
cd && wget https://dl.google.com/go/go1.13.1.linux-amd64.tar.gz && sudo tar -xvf go1.13.1.linux-amd64.tar.gz && sudo mv go /usr/local && export GOROOT=/usr/local/go && export GOPATH=$HOME/Projects/Proj1 && export PATH=$GOPATH/bin:$GOROOT/bin:$PATH && go version && go get github.com/OWASP/Amass
```

Ignore any error messages regarding what was pulled down.

2. Turn on support for Go Modules to ensure the correct dependency versions are used:

```bash
export GO111MODULE=on
```

3. Next, build the binary from the project source code:

```bash
cd /usr/local/go/src/github.com/OWASP/Amass

go install ./...
```

At this point, the binary should be in *$GOPATH/bin*. Several wordlists for performing DNS name alterations and brute forcing can be found in the following directory:

```bash
ls ~/go/src/github.com/OWASP/Amass/wordlist/
```

## Packages Maintained by the Amass Project

### Homebrew

For **Homebrew**, the following two commands will install Amass into your environment:

```bash
brew tap caffix/amass
brew install amass
```



## Packages Maintained by a Third-party

### Arch Linux

Details regarding this package can be found [here](https://aur.archlinux.org/packages/amass/)

### BlackArch Linux

Details regarding this package can be found [here](https://github.com/BlackArch/blackarch/blob/master/packages/amass/PKGBUILD)

### FreeBSD

```bash
cd /usr/ports/dns/amass/ && make install clean
pkg install amass
```

## Nix or NixOS

```bash
nix-env -f '<nixpkgs>' -iA amass
```

### Pentoo Linux

```bash
sudo emerge net-analyzer/amass
```

Periodically, execute the following command to update all packages:

```bash
sudo pentoo-updater
```

Go to the User's Guide[https://github.com/OWASP/Amass/blob/master/doc/user_guide.md] for additional information


## Example of Usage 

```bash
amass enum --passive -src -w /usr/share/wordlists/dnsmap.txt -d domain.com -o amassbrute.txt
```
