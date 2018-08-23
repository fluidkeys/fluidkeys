# Fluidkeys command line

[![Build Status](https://travis-ci.org/fluidkeys/fluidkeys.svg?branch=master)](https://travis-ci.org/fluidkeys/fluidkeys)

Fluidkeys helps teams protect themselves with strong encryption. It builds on the OpenPGP standard and is compatible with other OpenPGP software.

0.1 helps you create a key with a strong password and backs it up for you.

Once installed, run it with `fk`.

## Install on Debian / Ubuntu

1. Get our public key

```
sudo apt-key adv --keyserver pool.sks-keyservers.net --recv-key 0x36D46F41F57A1DF676730BE4EA53212450A89809
```

2. Add our apt repository

```
echo 'deb [arch=amd64] https://download.fluidkeys.com/desktop/apt any main' | sudo tee /etc/apt/sources.list.d/fluidkeys.list
```

3. Install

```
sudo apt update
sudo apt install fluidkeys
```

## Install on macOS

```
brew tap fluidkeys/tap
brew update
brew install fluidkeys
```

## Develop

If you want to hack on Fluidkeys locally you'll need [Go 1.10](https://golang.org/dl/) and [dep](https://github.com/golang/dep#installation).

Get dependencies:

```
make install_dependencies
```

Run:

```
make run
```
