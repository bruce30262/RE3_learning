FROM phusion/baseimage:latest
MAINTAINER bruce30262

# Set the locale
RUN locale-gen en_US.UTF-8  
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8

# apt-get
# not using dockerhub auto-build, so better fetch those packages from TW
RUN sed -i "s/archive.ubuntu.com/tw.archive.ubuntu.com/g" /etc/apt/sources.list
RUN dpkg --add-architecture i386 && apt-get update \
        && apt-get install build-essential -y \
        && apt-get install -y \
        sudo \
        git \
        gcc \
        g++ \
        make \
        cmake \
        python2.7\
        python2.7-dev\
        python-pip \
        python3-dev\
        python3-pip \
        wget \
        vim

# update pip & pip3
RUN sudo pip install --upgrade pip
RUN sudo pip3 install --upgrade pip

# install capstone and its python binding
RUN cd ~/ && git clone https://github.com/aquynh/capstone.git ~/capstone
RUN cd ~/capstone/ && ./make.sh && sudo ./make.sh install
RUN cd ~/capstone/bindings/python && sudo make install && sudo make install3

# install unicorn and its python binding
RUN sudo pip2 install unicorn
RUN sudo pip3 install unicorn

# install keystone and its python binding
RUN cd ~/ && git clone https://github.com/keystone-engine/keystone.git ~/keystone
RUN cd ~/keystone/ && mkdir build && cd ./build && ../make-share.sh
RUN cd ~/keystone/bindings/python && sudo make install && sudo make install3
# Bug in keystone install script , need to copy libkeystone.so to the correct path
RUN cp /root/keystone/build/llvm/lib/libkeystone.so /usr/local/lib/python2.7/dist-packages/keystone/
RUN cp /root/keystone/build/llvm/lib/libkeystone.so /usr/local/lib/python3.5/dist-packages/keystone/

# create dir for workspace
COPY test/ /root/

CMD ["/bin/bash"]
