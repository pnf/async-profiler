#!/ms/dist/fsf/PROJ/bash/4.3/bin/bash -vx                              

source paths-ms.sh

make clean
make
make debug

C=../install/common
E=../install/.exec/$ID_KVM

mkdir -p $C/java $E/bin $E/lib $E/lib-g $E/bin/build

cp build/jar/*.jar $C/java
cp -p build/lib/*.so $E/lib
cp -p build/lib-g/*.so $E/lib-g
cp -p build/bin/asprof $E/bin

# The shell script expects to find its companions in a build subdirectory
cd $E/bin/build
ln -fs ../../lib/libasyncProfiler.so
ln -fs ../asprof
