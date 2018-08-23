# Fluidkeys command line

[![Build Status](https://travis-ci.org/fluidkeys/fluidkeys.svg?branch=master)](https://travis-ci.org/fluidkeys/fluidkeys)

## Install on Debian / Ubuntu

### Get our public key

```
sudo apt-key adv --keyserver pool.sks-keyservers.net --recv-key 0x36D46F41F57A1DF676730BE4EA53212450A89809
```

### Add our apt repository

```
echo 'deb [arch=amd64] https://download.fluidkeys.com/desktop/apt any main' | sudo tee /etc/apt/sources.list.d/fluidkeys.list
```

### Install

```
sudo apt update
sudo apt install fluidkeys
```

## Install on macOS

### Using homebrew

```
brew tap fluidkeys/tap
brew update
brew install fluidkeys
```

## Develop

Get dependencies:

```
make install_dependencies
```

Run:

```
make run
```
