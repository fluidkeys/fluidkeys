# Fluidkeys command line

## Debian / Ubuntu

### Get our public key

```
sudo apt-key adv --keyserver pool.sks-keyservers.net --recv-key 0xA999B7498D1A8DC473E53C92309F635DAD1B5517
```

### Add our apt repository

```
echo 'deb [arch=amd64] https://download.fluidkeys.com any main' | sudo tee /etc/apt/sources.list.d/fluidkeys.list
```

### Install

```
sudo apt update
sudo apt install fluidkeys
```
