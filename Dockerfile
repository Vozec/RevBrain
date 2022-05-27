FROM ubuntu

ENV USER angr
ENV ROOTPWD root
ENV SHELL /bin/bash 

#======================================================

ENV DOCUMENT_ROOT /home/${USER}

RUN \
    apt-get -y -qq update; \
    apt-get -y -qq install python3 nano sudo python3-pip git gdb curl wget tree ltrace strace checksec; \
    pip install archinfo pyvex claripy cle angr; \
    git clone https://github.com/radareorg/radare2 ; \
    radare2/sys/install.sh; \
    git clone https://github.com/longld/peda.git ~/peda; \
    echo "source ~/peda/peda.py" >> ~/.gdbinit; \
    pip uninstall protobuff; \
    pip install protobuf==3.20.1 ; \
    python3 -m pip install --upgrade pwntools r2pipe ;

RUN \
    useradd -m -s /bin/bash ${USER}; \
    echo "${USER}:${USER}" | chpasswd; \
    echo "root:${ROOTPWD}" | chpasswd; \
    echo "cd ${DOCUMENT_ROOT}" >> /root/.bashrc;
    
RUN \
    curl https://github.com/deluan/zsh-in-docker/releases/download/v1.1.2/zsh-in-docker.sh -o /tmp/zsh-in-docker.sh;\
    chmod +x /tmp/zsh-in-docker.sh; \
    cd /tmp ;echo 'y' | ./zsh-in-docker.sh -t jispwoso;

VOLUME ${DOCUMENT_ROOT}
WORKDIR ${DOCUMENT_ROOT}

ENTRYPOINT /bin/bash
CMD ["sleep", "infinity"]