
# [![OWASP Logo](../images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/) - Installation Guide

[![Packaging status](https://repology.org/badge/vertical-allrepos/amass.svg)](https://repology.org/metapackage/amass/versions)
[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/amass)

## Prebuilt Binaries

A [precompiled version is available](https://github.com/OWASP/Amass/releases) with each release.

Using this installation option on macOS is could result in an 'unidentified developer' warning. This can be resolved by following the steps below:

1. Close the error message popup
2. In macOS, go to "System Preferences" > "Security & Privacy"
3. At the bottom of the dialog, there is a message saying that "amass' was blocked. Next to it click "Open anyway"
4. The initial error message could pop up again, but this time with the option to click "Open" to run amass
5. This only needs to be done once, amass will now run every time

## Using Docker

1. Build the [Docker](https://docs.docker.com/) image:

```bash
docker build -t amass https://github.com/OWASP/Amass.git
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

## From Source

If you prefer to build your own binary from the latest release of the source code, make sure you have a correctly configured **Go >= 1.14** environment. More information about how to achieve this can be found [on the golang website.](https://golang.org/doc/install).

Simply execute the following commands:

1. Download OWASP Amass:

```bash
GO111MODULE=on go get -v github.com/OWASP/Amass/v3/...
```

At this point, the binary should be in *$GOPATH/bin*.

2. If you'd like to rebuild the binary from the project source code:

```bash
cd $GOPATH/src/github.com/OWASP/Amass

go install ./...
```

Several wordlists for performing DNS name alterations and brute forcing can be found in the following directory:

```bash
ls $GOPATH/src/github.com/OWASP/Amass/examples/wordlists/
```

## Packages Maintained by the Amass Project

### Homebrew

For **Homebrew**, the following two commands will install Amass into your environment:

```bash
brew tap caffix/amass
brew install amass
```

### Snapcraft

If your operating environment supports [Snap](https://docs.snapcraft.io/core/install), you can [click here to install](https://snapcraft.io/amass), or perform the following from the command-line:

```bash
sudo snap install amass
```

Add the Snap bin directory to your PATH:

```bash
export PATH=$PATH:/snap/bin
```

Periodically, execute the following command to update all your snap packages:

```bash
sudo snap refresh
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
