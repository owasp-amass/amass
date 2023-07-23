
# [![OWASP Logo](../images/owasp_logo.png) OWASP Amass](https://owasp.org/www-project-amass/) - Installation Guide

[![Packaging status](https://repology.org/badge/vertical-allrepos/amass.svg)](https://repology.org/metapackage/amass/versions)

## Prebuilt Binaries

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

## From Source

If you prefer to build your own binary from the latest release of the source code, make sure you have a correctly configured **Go >= 1.18** environment. More information about how to achieve this can be found [on the golang website.](https://golang.org/doc/install).

Simply execute the following command:

```bash
go install -v github.com/owasp-amass/amass/v4/...@master
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
