cd db-4.8.30.NC/build_unix
BDB_PREFIX=$(pwd)/build
../dist/configure --disable-shared --enable-cxx --with-pic --prefix=$BDB_PREFIX
sudo make install

sudo apt-get update
sudo apt-get install libevent-dev
cd ../../bitcoin
./autogen.sh
./configure CPPFLAGS="-I${BDB_PREFIX}/include/ -O2" LDFLAGS="-L${BDB_PREFIX}/lib/" --disable-wallet --enable-debug --without-gui
make -j2
sudo make install
