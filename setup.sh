apt-get -y -qq update
apt-get -y -qq install python3 nano python3-pip gdb ltrace strace checksec
pip install archinfo pyvex claripy cle angr
git clone https://github.com/radareorg/radare2 
radare2/sys/install.sh
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
pip uninstall protobuff
pip install protobuf==3.20.1 
python3 -m pip install --upgrade pwntools r2pipe ;