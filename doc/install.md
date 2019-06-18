
# [![OWASP Logo](https://github.com/OWASP/Amass/blob/master/images/owasp_logo.png) OWASP Amass](https://www.owasp.org/index.php/OWASP_Amass_Project) - Installation Guide

[![Packaging status](https://repology.org/badge/vertical-allrepos/amass.svg)](https://repology.org/metapackage/amass/versions)
[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/amass)

## Prebuilt Binaries

A [precompiled version is available](https://github.com/OWASP/Amass/releases) with each release.

## Using Docker

1. Build the [Docker](https://docs.docker.com/) image:

```bash
sudo docker build -t amass https://github.com/OWASP/Amass.git
```

2. Run the Docker image:

```bash
sudo docker run amass enum --passive -d example.com
```

The wordlists maintained in the Amass git repository are available in `/wordlists/` within the docker container. For example, to use `all.txt`:

```bash
sudo docker run amass enum -brute -w /wordlists/all.txt -d example.com
```

## From Source

If you prefer to build your own binary from the latest release of the source code, make sure you have a correctly configured **Go >= 1.10** environment. More information about how to achieve this can be found [on the golang website.](https://golang.org/doc/install) Then, take the following steps:

1. Download OWASP Amass:

```bash
go get -u github.com/OWASP/Amass/...
```

2. If you wish to rebuild the binaries from the source code:

```bash
cd $GOPATH/src/github.com/OWASP/Amass

go install ./...
```

At this point, the binaries should be in *$GOPATH/bin*.

3. Several wordlists can be found in the following directory:

```bash
ls $GOPATH/src/github.com/OWASP/Amass/wordlists/
```

## Packages Maintained by the Amass Project

### Homebrew (macOS)

For **Homebrew** on **Mac**, the following two commands will install Amass into your macOS environment:

```bash
brew tap caffix/amass
brew install amass
```

### Snapcraft

If your operating environment supports [Snap](https://docs.snapcraft.io/core/install), you can [click here to install](https://snapcraft.io/amass), or perform the following from the command-line:

```bash
sudo snap install amass
```

On **Kali**, follow these steps to install Snap and Amass + use AppArmor (for autoload):

```bash
sudo apt install snapd
sudo systemctl start snapd
sudo systemctl enable snapd
sudo systemctl start apparmor
sudo systemctl enable apparmor
```

Add the Snap bin directory to your PATH:

```bash
export PATH=$PATH:/snap/bin
```

Periodically, execute the following command to update all your snap packages:

```bash
sudo snap refresh
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
