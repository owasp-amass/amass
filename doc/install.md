
# [![OWASP Logo](../images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/) - Installation Guide

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
sudo apt install snapd && sudo systemctl start snapd && sudo systemctl enable snapd && sudo systemctl start apparmor && sudo systemctl enable apparmor && export PATH="$PATH:/snap/bin" && snap install go --classic && sudo snap install amass && amass -version 
```

Periodically, execute the following command to update all your snap packages:

```bash
sudo snap refresh
```
=======
A [precompiled version is available](https://github.com/owasp-amass/amass/releases) with each release.

Using this installation option on macOS is could result in an 'unidentified developer' warning. This can be resolved by following the steps below:

1. Close the error message popup
2. In macOS, go to "System Preferences" > "Security & Privacy"
3. At the bottom of the dialog, there is a message saying that "amass' was blocked. Next to it click "Open anyway"
4. The initial error message could pop up again, but this time with the option to click "Open" to run amass
5. This only needs to be done once, amass will now run every time


## Using Docker

1. Build the [Docker](https://docs.docker.com/) image:

```bash
docker build -t amass https://github.com/owasp-amass/amass.git
```

2. Run the Docker image:

```bash
docker run -v OUTPUT_DIR_PATH:/.config/amass/ amass enum --list
```

The volume argument allows the Amass graph database to persist between executions and output files to be accessed on the host system. The first field (left of the colon) of the volume option is the amass output directory that is external to Docker, while the second field is the path, internal to Docker, where amass will write the output files.

The wordlists maintained in the Amass git repository are available in `/examples/wordlists/` within the docker container. For example, to use `all.txt`:

```bash
docker run -v OUTPUT_DIR_PATH:/.config/amass/ amass enum -brute -w /wordlists/all.txt -share -d example.com
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

If you prefer to build your own binary from the latest release of the source code, make sure you have a correctly configured **Go >= 1.18** environment. More information about how to achieve this can be found [on the golang website.](https://golang.org/doc/install).


Simply execute the following command:

```bash
go install -v github.com/owasp-amass/amass/v4/...@master
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

At this point, the binary should be in *$GOPATH/bin*.


## Packages Maintained by the Amass Project

### Homebrew

For **Homebrew**, the following two commands will install Amass into your environment:

```bash
brew tap owasp-amass/amass
brew install amass
```


## Packages Maintained by a Third Party

### Arch Linux

Details regarding this package can be found [here](https://aur.archlinux.org/packages/amass/)

### BlackArch Linux

Details regarding this package can be found [here](https://github.com/BlackArch/blackarch/blob/master/packages/amass/PKGBUILD)

### DragonFly BSD

```bash
pkg upgrade
pkg install amass
```

### FreeBSD

```bash
cd /usr/ports/dns/amass/ && make install clean
pkg install amass
```


### Kali Linux

OWASP Amass is installed by default and can be managed like any other Kali package:

```bash
apt-get update
apt-get install amass
```

## Nix or NixOS

```bash
nix-env -f '<nixpkgs>' -iA amass
```

### Parrot Linux

```bash
apt-get update
apt-get install amass
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
